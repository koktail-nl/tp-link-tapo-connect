import axios, { AxiosInstance } from "axios";

/** Time a device on the local network gets to answer one request. */
export const DEVICE_REQUEST_TIMEOUT_MS = 5000;

/**
 * HTTP client for requests to a device. A request whose socket stays idle for the timeout is
 * aborted, which closes the socket and rejects with code ECONNABORTED. The timeout measures
 * inactivity, so a device that keeps sending data within it is not aborted.
 */
export const deviceHttp: AxiosInstance = axios.create({
  timeout: DEVICE_REQUEST_TIMEOUT_MS,
});

/** A JSON object as a device sends it, before its fields are checked. */
export type DeviceResponse = Readonly<Record<string, unknown>>;

const isRecord = (value: unknown): value is DeviceResponse =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** Reads a device response as a JSON object, or throws when it is any other value. */
export const readDeviceResponse = (value: unknown): DeviceResponse => {
  if (!isRecord(value)) {
    throw new Error("Unexpected device response");
  }
  return value;
};

/**
 * Decrypts device content and parses it as JSON. Content that does not decrypt or is not JSON
 * throws a SyntaxError whose message leaves the content out, so it never reaches a log.
 */
export const readDecryptedJson = (decrypt: () => Buffer): unknown => {
  try {
    return JSON.parse(decrypt().toString());
  } catch {
    throw new SyntaxError("Device response does not decrypt to JSON");
  }
};

/** Reads the session cookie, without its attributes, from the headers of a device response. */
export const readSessionCookie = (headers: unknown): string => {
  const setCookie = isRecord(headers) ? headers["set-cookie"] : undefined;
  const cookie = Array.isArray(setCookie) ? setCookie[0] : undefined;
  if (typeof cookie !== "string") {
    throw new Error("Device response carries no session cookie");
  }
  const end = cookie.indexOf(";");
  return end === -1 ? cookie : cookie.substring(0, end);
};
