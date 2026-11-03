import {
  base64Encode,
  decrypt,
  encrypt,
  generateKeyPair,
  readDeviceKey,
  shaDigest,
} from "./tplink-cipher";
import { TapoDeviceKey } from "./types";
import { TapoDevice } from "./tapo-device";
import { checkError } from "./tapo-utils";
import {
  DeviceResponse,
  deviceHttp,
  readDeviceResponse,
  readSessionCookie,
} from "./device-http";

const KEY_LENGTH = 16;
const IV_END = 32;

/**
 * Logs in to a device over the legacy secure passthrough protocol.
 *
 * Throws the request error when the device fails or does not answer, an Error for a device error
 * code, `Device response carries no key`, `... no session cookie` or `... no token` for a handshake
 * or login without them, `Unexpected device response` for a result that is not an object, and the
 * decryption error of `readDeviceKey`.
 */
export const loginDeviceByIp = async (
  email: string,
  password: string,
  deviceIp: string,
): Promise<ReturnType<typeof TapoDevice>> => {
  const deviceKey = await handshake(deviceIp);
  const loginDeviceRequest = {
    method: "login_device",
    params: {
      username: base64Encode(shaDigest(email)),
      password: base64Encode(password),
    },
    requestTimeMils: 0,
  };

  const loginDeviceResponse = readDeviceResponse(
    await securePassthrough(loginDeviceRequest, deviceKey),
  );
  deviceKey.token = readString(loginDeviceResponse.token, "token");

  const send = (request: unknown) => securePassthrough(request, deviceKey);

  return TapoDevice({
    send,
  });
};

const handshake = async (deviceIp: string): Promise<TapoDeviceKey> => {
  const keyPair = await generateKeyPair();

  const handshakeRequest = {
    method: "handshake",
    params: {
      key: keyPair.publicKey,
    },
  };
  const response = await deviceHttp({
    method: "post",
    url: `http://${deviceIp}/app`,
    data: handshakeRequest,
  });

  const result = readResult(response.data);
  const sessionCookie = readSessionCookie(response.headers);
  const deviceKey = readDeviceKey(
    readString(result.key, "key"),
    keyPair.privateKey,
  );

  return {
    key: deviceKey.subarray(0, KEY_LENGTH),
    iv: deviceKey.subarray(KEY_LENGTH, IV_END),
    deviceIp,
    sessionCookie,
  };
};

/**
 * Sends one request over a legacy session.
 *
 * Throws the request error when the device fails or does not answer, an Error for a device error
 * code around or inside the encrypted response, `Unexpected device response` for a response or
 * result that is not an object, `Device response carries no response` for a result without
 * encrypted content, and a SyntaxError for content that does not decrypt to JSON.
 */
export const securePassthrough = async (
  deviceRequest: unknown,
  deviceKey: TapoDeviceKey,
): Promise<unknown> => {
  const encryptedRequest = encrypt(deviceRequest, deviceKey);
  const securePassthroughRequest = {
    method: "securePassthrough",
    params: {
      request: encryptedRequest,
    },
  };

  const response = await deviceHttp({
    method: "post",
    url: `http://${deviceKey.deviceIp}/app?token=${deviceKey.token}`,
    data: securePassthroughRequest,
    headers: {
      Cookie: deviceKey.sessionCookie,
    },
  });

  const result = readResult(response.data);
  const decryptedResponse = readDeviceResponse(
    decrypt(readString(result.response, "response"), deviceKey),
  );
  checkError(decryptedResponse);
  return decryptedResponse.result;
};

// A device error in the response is raised before its result is read.
const readResult = (data: unknown): DeviceResponse => {
  const response = readDeviceResponse(data);
  checkError(response);
  return readDeviceResponse(response.result);
};

const readString = (value: unknown, field: string): string => {
  if (typeof value !== "string") {
    throw new Error(`Device response carries no ${field}`);
  }
  return value;
};
