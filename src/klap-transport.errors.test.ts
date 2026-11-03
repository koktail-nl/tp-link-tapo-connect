import { createServer, IncomingMessage, Server, ServerResponse } from "http";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "crypto";
import { loginDeviceByIp, ProtocolUnsupportedError } from "./klap-transport";

const email = "user@example.com";
const password = "password";

const sha = (algorithm: string, ...parts: Buffer[]) =>
  createHash(algorithm).update(Buffer.concat(parts)).digest();
const authHash = sha(
  "sha256",
  sha("sha1", Buffer.from(email)),
  sha("sha1", Buffer.from(password)),
);

type Reply = (response: ServerResponse) => void;
type DeviceBehaviour = {
  handshake1?: Reply;
  handshake2?: Reply;
  request?: (
    respond: (payload: string) => void,
    response: ServerResponse,
  ) => void;
};

const readBody = async (request: IncomingMessage) => {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
};

const status =
  (code: number): Reply =>
  (response) => {
    response.writeHead(code);
    response.end();
  };

// A KLAP device that answers each step as `behaviour` sets, and as a real device otherwise.
const startDevice = async (behaviour: DeviceBehaviour) => {
  const remoteSeed = randomBytes(16);
  let localSeed = Buffer.alloc(16);
  const server: Server = createServer(async (request, response) => {
    const body = await readBody(request);
    const url = new URL(request.url ?? "", "http://device");
    if (url.pathname === "/app/handshake1") {
      if (behaviour.handshake1) return behaviour.handshake1(response);
      localSeed = body;
      response.writeHead(200, {
        "Set-Cookie": "TP_SESSIONID=session;TIMEOUT=86400",
      });
      return response.end(
        Buffer.concat([
          remoteSeed,
          sha("sha256", localSeed, remoteSeed, authHash),
        ]),
      );
    }
    if (url.pathname === "/app/handshake2") {
      return (behaviour.handshake2 ?? status(200))(response);
    }
    const derive = (label: string) =>
      sha("sha256", Buffer.from(label), localSeed, remoteSeed, authHash);
    const key = derive("lsk").subarray(0, 16);
    const iv = Buffer.alloc(16);
    derive("iv").copy(iv, 0, 0, 12);
    iv.writeInt32BE(Number(url.searchParams.get("seq")), 12);
    const decipher = createDecipheriv("aes-128-cbc", key, iv);
    const received = JSON.parse(
      Buffer.concat([
        decipher.update(body.subarray(32)),
        decipher.final(),
      ]).toString(),
    );
    requests.push(received);
    const respond = (payload: string) => {
      const cipher = createCipheriv("aes-128-cbc", key, iv);
      response.writeHead(200);
      response.end(
        Buffer.concat([
          Buffer.alloc(32),
          cipher.update(payload),
          cipher.final(),
        ]),
      );
    };
    (behaviour.request ?? ((reply) => reply('{"error_code":0,"result":{}}')))(
      respond,
      response,
    );
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (typeof address !== "object" || address === null) {
    throw new Error("Device server has no port");
  }
  servers.push(server);
  return `127.0.0.1:${address.port}`;
};

let servers: Server[] = [];
let requests: unknown[] = [];

afterEach(async () => {
  await Promise.all(
    servers.map((server) => new Promise((resolve) => server.close(resolve))),
  );
  servers = [];
  requests = [];
});

const login = async (behaviour: DeviceBehaviour) =>
  loginDeviceByIp(email, password, await startDevice(behaviour));

it("a device without the KLAP endpoint reports the protocol as unsupported", async () => {
  await expect(login({ handshake1: status(404) })).rejects.toThrow(
    "Klap protocol not supported",
  );
});

it("a device that refuses handshake1 reports invalid credentials", async () => {
  await expect(login({ handshake1: status(403) })).rejects.toThrow(
    "Invalid credentials - device rejected authentication",
  );
});

it("a handshake1 failure keeps the request error as cause", async () => {
  await expect(login({ handshake1: status(500) })).rejects.toMatchObject({
    message: expect.stringMatching(/^handshake1 failed: /),
    cause: { response: { status: 500 } },
  });
});

it("a device that cannot be reached fails handshake1 with the network error as cause", async () => {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (typeof address !== "object" || address === null) {
    throw new Error("Device server has no port");
  }
  await new Promise((resolve) => server.close(resolve));
  await expect(
    loginDeviceByIp(email, password, `127.0.0.1:${address.port}`),
  ).rejects.toMatchObject({
    message: expect.stringMatching(/^handshake1 failed: /),
    cause: { code: "ECONNREFUSED" },
  });
});

it("a handshake1 request that cannot be made keeps its error as cause", async () => {
  await expect(
    loginDeviceByIp(email, password, "127.0.0.1:99999"),
  ).rejects.toMatchObject({
    message: expect.stringMatching(/^handshake1 failed: RangeError/),
    cause: expect.objectContaining({ code: "ERR_SOCKET_BAD_PORT" }),
  });
});

it("a handshake1 response shorter than a seed and hash fails the handshake", async () => {
  const short: Reply = (response) => {
    response.writeHead(200, { "Set-Cookie": "TP_SESSIONID=session" });
    response.end(Buffer.alloc(16));
  };
  await expect(login({ handshake1: short })).rejects.toThrow(
    "handshake1 failed: response too short",
  );
});

it("a handshake1 response without a session cookie is rejected", async () => {
  const cookieless: Reply = (response) => {
    response.writeHead(200);
    response.end(Buffer.alloc(48));
  };
  await expect(login({ handshake1: cookieless })).rejects.toThrow(
    "Device response carries no session cookie",
  );
});

it("a device hash for other credentials reports the email or password as incorrect", async () => {
  await expect(
    loginDeviceByIp(email, "other", await startDevice({})),
  ).rejects.toThrow("email or password incorrect");
});

it("a handshake2 failure keeps the request error as cause", async () => {
  await expect(login({ handshake2: status(500) })).rejects.toMatchObject({
    message: expect.stringMatching(/^handshake2 failed: /),
    cause: { response: { status: 500 } },
  });
});

it("a command reaches the device decrypted", async () => {
  const device = await login({});
  await device.turnOn();
  expect(requests).toEqual([
    expect.objectContaining({
      method: "set_device_info",
      params: expect.objectContaining({ device_on: true }),
    }),
  ]);
});

it("a rejected request keeps the HTTP status of the request error", async () => {
  const device = await login({
    request: (_respond, response) => status(403)(response),
  });
  await expect(device.turnOn()).rejects.toMatchObject({
    isAxiosError: true,
    response: { status: 403 },
  });
});

it("a response that does not decrypt to JSON is a SyntaxError without the content", async () => {
  const device = await login({ request: (respond) => respond("secret-token") });
  await expect(device.turnOn()).rejects.toMatchObject({
    name: "SyntaxError",
    message: "Device response does not decrypt to JSON",
  });
});

it("a response that does not decrypt is a SyntaxError", async () => {
  const device = await login({
    request: (_respond, response) => status(200)(response),
  });
  await expect(device.turnOn()).rejects.toMatchObject({
    name: "SyntaxError",
    message: "Device response does not decrypt to JSON",
  });
});

it("a device error code in the response is thrown", async () => {
  const device = await login({
    request: (respond) => respond('{"error_code":-1002}'),
  });
  await expect(device.turnOn()).rejects.toThrow(
    "Transport not available error",
  );
});

it("a protocol unsupported error carries its type", () => {
  expect(new ProtocolUnsupportedError("unsupported")).toMatchObject({
    type: "ProtocolUnsupportedError",
    message: "unsupported",
  });
});
