import { createServer, IncomingMessage, Server, ServerResponse } from "http";
import { createCipheriv, createDecipheriv, randomBytes } from "crypto";
import {
  loginDeviceByIp,
  securePassthrough,
} from "./secure-passthrough-transport";
import { TapoDeviceKey } from "./types";

type Handler = (body: unknown, response: ServerResponse) => void;

const readJson = async (request: IncomingMessage): Promise<unknown> => {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return JSON.parse(Buffer.concat(chunks).toString());
};

const reply =
  (payload: unknown, headers: Record<string, string> = {}): Handler =>
  (_body, response) => {
    response.writeHead(200, { "Content-Type": "application/json", ...headers });
    response.end(JSON.stringify(payload));
  };

let servers: Server[] = [];

afterEach(async () => {
  await Promise.all(
    servers.map((server) => new Promise((resolve) => server.close(resolve))),
  );
  servers = [];
});

const startDevice = async (handler: Handler) => {
  const server = createServer(async (request, response) =>
    handler(await readJson(request), response),
  );
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (typeof address !== "object" || address === null) {
    throw new Error("Device server has no port");
  }
  servers.push(server);
  return `127.0.0.1:${address.port}`;
};

const login = async (handler: Handler) =>
  loginDeviceByIp("user@example.com", "password", await startDevice(handler));

it("a device error code in the handshake is thrown", async () => {
  await expect(login(reply({ error_code: -1010 }))).rejects.toThrow(
    "Invalid public key length",
  );
});

it("a handshake without a key is rejected", async () => {
  await expect(
    login(
      reply({ error_code: 0, result: {} }, { "Set-Cookie": "TP_SESSIONID=s" }),
    ),
  ).rejects.toThrow("Device response carries no key");
});

it("a handshake without a result is rejected", async () => {
  await expect(login(reply({ error_code: 0, result: [] }))).rejects.toThrow(
    "Unexpected device response",
  );
});

const readEncryptedRequest = (body: unknown): string => {
  const params =
    typeof body === "object" && body !== null && "params" in body
      ? body.params
      : undefined;
  const request =
    typeof params === "object" && params !== null && "request" in params
      ? params.request
      : undefined;
  if (typeof request !== "string") throw new Error("Request is not encrypted");
  return request;
};

const sessionKey = (deviceIp: string): TapoDeviceKey => ({
  key: randomBytes(16),
  iv: randomBytes(16),
  deviceIp,
  sessionCookie: "TP_SESSIONID=s",
  token: "token",
});

const encrypted = (deviceKey: TapoDeviceKey, content: string) => {
  const cipher = createCipheriv("aes-128-cbc", deviceKey.key, deviceKey.iv);
  return Buffer.concat([cipher.update(content), cipher.final()]).toString(
    "base64",
  );
};

// A legacy session that answers each request with `content`, encrypted with the session key.
const sessionAnswering = async (content: (key: TapoDeviceKey) => unknown) => {
  let deviceKey: TapoDeviceKey | undefined;
  const deviceIp = await startDevice((body, response) => {
    if (!deviceKey) throw new Error("Session key missing");
    reply(content(deviceKey))(body, response);
  });
  deviceKey = sessionKey(deviceIp);
  return deviceKey;
};

it("a request reaches the device decrypted and returns the result", async () => {
  let received: unknown;
  let deviceKey: TapoDeviceKey | undefined;
  const deviceIp = await startDevice((body, response) => {
    if (!deviceKey) throw new Error("Session key missing");
    const decipher = createDecipheriv(
      "aes-128-cbc",
      deviceKey.key,
      deviceKey.iv,
    );
    const request = readEncryptedRequest(body);
    received = JSON.parse(
      Buffer.concat([
        decipher.update(Buffer.from(request, "base64")),
        decipher.final(),
      ]).toString(),
    );
    reply({
      error_code: 0,
      result: {
        response: encrypted(deviceKey, '{"error_code":0,"result":{"on":1}}'),
      },
    })(body, response);
  });
  deviceKey = sessionKey(deviceIp);
  await expect(
    securePassthrough({ method: "get_device_info" }, deviceKey),
  ).resolves.toEqual({ on: 1 });
  expect(received).toEqual({ method: "get_device_info" });
});

it("a device error code around the encrypted response is thrown", async () => {
  const deviceKey = await sessionAnswering(() => ({ error_code: 9999 }));
  await expect(securePassthrough({}, deviceKey)).rejects.toThrow(
    "Session Timeout",
  );
});

it("a result without an encrypted response is rejected", async () => {
  const deviceKey = await sessionAnswering(() => ({
    error_code: 0,
    result: {},
  }));
  await expect(securePassthrough({}, deviceKey)).rejects.toThrow(
    "Device response carries no response",
  );
});

it("an encrypted response that is not JSON is a SyntaxError without the content", async () => {
  const deviceKey = await sessionAnswering((key) => ({
    error_code: 0,
    result: { response: encrypted(key, "secret-token") },
  }));
  await expect(securePassthrough({}, deviceKey)).rejects.toMatchObject({
    name: "SyntaxError",
    message: "Device response does not decrypt to JSON",
  });
});

it("an encrypted response that does not decrypt is a SyntaxError", async () => {
  const deviceKey = await sessionAnswering(() => ({
    error_code: 0,
    result: { response: "AAAA" },
  }));
  await expect(securePassthrough({}, deviceKey)).rejects.toMatchObject({
    name: "SyntaxError",
    message: "Device response does not decrypt to JSON",
  });
});

it("a device error code inside the encrypted response is thrown", async () => {
  const deviceKey = await sessionAnswering((key) => ({
    error_code: 0,
    result: { response: encrypted(key, '{"error_code":-1501}') },
  }));
  await expect(securePassthrough({}, deviceKey)).rejects.toThrow(
    "Invalid credentials",
  );
});
