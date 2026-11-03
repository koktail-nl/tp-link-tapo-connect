import { createServer, Server } from "http";
import { Socket } from "net";
import {
  DEVICE_REQUEST_TIMEOUT_MS,
  deviceHttp,
  readDeviceResponse,
  readSessionCookie,
} from "./device-http";
import { loginDeviceByIp } from "./klap-transport";

// A device that accepts the connection and never answers.
const silentDevice = async () => {
  const sockets: Socket[] = [];
  const server: Server = createServer(() => undefined);
  server.on("connection", (socket) => sockets.push(socket));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (typeof address !== "object" || address === null) {
    throw new Error("Device server has no port");
  }
  return { server, sockets, address: `127.0.0.1:${address.port}` };
};

let device: Awaited<ReturnType<typeof silentDevice>>;

beforeEach(async () => {
  device = await silentDevice();
});

afterEach(async () => {
  device.server.closeAllConnections();
  await new Promise((resolve) => device.server.close(resolve));
});

it("a request to a device that does not answer aborts at the timeout and closes the socket", async () => {
  const started = Date.now();
  await expect(
    deviceHttp.post(`http://${device.address}/app/request`, ""),
  ).rejects.toMatchObject({ code: "ECONNABORTED" });
  const elapsed = Date.now() - started;
  expect(elapsed).toBeGreaterThanOrEqual(DEVICE_REQUEST_TIMEOUT_MS - 50);
  expect(elapsed).toBeLessThan(DEVICE_REQUEST_TIMEOUT_MS + 1000);
  await new Promise((resolve) => setImmediate(resolve));
  expect(device.sockets).toHaveLength(1);
  expect(device.sockets.every((socket) => socket.destroyed)).toBe(true);
});

it("a KLAP login on a device that does not answer fails at the timeout", async () => {
  await expect(
    loginDeviceByIp("user@example.com", "password", device.address),
  ).rejects.toThrow(/^handshake1 failed: Error: timeout/);
});

it.each([
  ["with attributes", "TP_SESSIONID=abc;TIMEOUT=86400"],
  ["without attributes", "TP_SESSIONID=abc"],
])("a session cookie %s is read without its attributes", (_name, cookie) => {
  expect(readSessionCookie({ "set-cookie": [cookie] })).toBe(
    "TP_SESSIONID=abc",
  );
});

it.each([
  ["no headers", undefined],
  ["no set-cookie header", {}],
  ["an empty set-cookie header", { "set-cookie": [] }],
  [
    "a set-cookie header of another shape",
    { "set-cookie": "TP_SESSIONID=abc" },
  ],
])("a response with %s has no session cookie", (_name, headers) => {
  expect(() => readSessionCookie(headers)).toThrow(
    "Device response carries no session cookie",
  );
});

it.each([
  ["null", null],
  ["a string", "error"],
  ["an array", []],
])("a device response of %s is rejected", (_name, value) => {
  expect(() => readDeviceResponse(value)).toThrow("Unexpected device response");
});

it("a device response object is returned as is", () => {
  const response = { error_code: 0, result: {} };
  expect(readDeviceResponse(response)).toBe(response);
});
