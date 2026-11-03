import { createServer, IncomingMessage, Server } from "http";
import { createCipheriv, createDecipheriv, randomBytes } from "crypto";
import { loginDeviceByIp } from "./secure-passthrough-transport";

// Node 22 no longer decrypts RSA with PKCS#1 v1.5 padding, so the device key is taken as sent.
const deviceKey = randomBytes(32);
jest.mock("./tplink-cipher", () => ({
  ...jest.requireActual<object>("./tplink-cipher"),
  readDeviceKey: () => deviceKey,
}));

const key = deviceKey.subarray(0, 16);
const iv = deviceKey.subarray(16, 32);

const readJson = async (request: IncomingMessage): Promise<unknown> => {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return JSON.parse(Buffer.concat(chunks).toString());
};

const decryptRequest = (body: unknown): unknown => {
  const params =
    typeof body === "object" && body !== null && "params" in body
      ? body.params
      : undefined;
  const request =
    typeof params === "object" && params !== null && "request" in params
      ? params.request
      : undefined;
  if (typeof request !== "string") throw new Error("Request is not encrypted");
  const decipher = createDecipheriv("aes-128-cbc", key, iv);
  return JSON.parse(
    Buffer.concat([
      decipher.update(Buffer.from(request, "base64")),
      decipher.final(),
    ]).toString(),
  );
};

const encrypt = (content: unknown) => {
  const cipher = createCipheriv("aes-128-cbc", key, iv);
  return Buffer.concat([
    cipher.update(JSON.stringify(content)),
    cipher.final(),
  ]).toString("base64");
};

type Seen = { url: string; cookie: string | undefined; request: unknown };

// A legacy device whose login answers with `loginResult` and every other request with an empty result.
const startDevice = async (loginResult: unknown) => {
  const seen: Seen[] = [];
  const server = createServer(async (request, response) => {
    const body = await readJson(request);
    response.writeHead(200, {
      "Content-Type": "application/json",
      "Set-Cookie": "TP_SESSIONID=session;TIMEOUT=1440",
    });
    if (request.url === "/app") {
      return response.end(
        JSON.stringify({ error_code: 0, result: { key: "key" } }),
      );
    }
    const decrypted = decryptRequest(body);
    seen.push({
      url: request.url ?? "",
      cookie: request.headers.cookie,
      request: decrypted,
    });
    const result =
      typeof decrypted === "object" &&
      decrypted !== null &&
      "method" in decrypted &&
      decrypted.method === "login_device"
        ? loginResult
        : {};
    response.end(
      JSON.stringify({
        error_code: 0,
        result: { response: encrypt({ error_code: 0, result }) },
      }),
    );
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (typeof address !== "object" || address === null) {
    throw new Error("Device server has no port");
  }
  servers.push(server);
  return { seen, deviceIp: `127.0.0.1:${address.port}` };
};

let servers: Server[] = [];

afterEach(async () => {
  await Promise.all(
    servers.map((server) => new Promise((resolve) => server.close(resolve))),
  );
  servers = [];
});

it("a command after a legacy login carries the session token and cookie", async () => {
  const { seen, deviceIp } = await startDevice({ token: "token" });
  const device = await loginDeviceByIp(
    "user@example.com",
    "password",
    deviceIp,
  );
  await device.turnOn();
  expect(seen[seen.length - 1]).toEqual({
    url: "/app?token=token",
    cookie: "TP_SESSIONID=session",
    request: expect.objectContaining({ method: "set_device_info" }),
  });
});

it("a legacy login whose result is not an object is rejected", async () => {
  const { deviceIp } = await startDevice("token");
  await expect(
    loginDeviceByIp("user@example.com", "password", deviceIp),
  ).rejects.toThrow("Unexpected device response");
});

it("a legacy login without a token is rejected", async () => {
  const { deviceIp } = await startDevice({});
  await expect(
    loginDeviceByIp("user@example.com", "password", deviceIp),
  ).rejects.toThrow("Device response carries no token");
});
