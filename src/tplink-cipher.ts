import crypto from "crypto";
import util from "util";
import type { TapoDeviceKey } from "./types";
import { readDecryptedJson } from "./device-http";

const RSA_CIPHER_ALGORITHM = "rsa";
const RSA_MODULUS_LENGTH = 1024;
const AES_CIPHER_ALGORITHM = "aes-128-cbc";
const PASSPHRASE = "top secret";

const generateRsaKeyPair = util.promisify(crypto.generateKeyPair);

/** Generates the RSA key pair a legacy handshake hands its public key from. */
export const generateKeyPair = (): Promise<{
  publicKey: string;
  privateKey: string;
}> =>
  generateRsaKeyPair(RSA_CIPHER_ALGORITHM, {
    modulusLength: RSA_MODULUS_LENGTH,
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs1",
      format: "pem",
      cipher: "aes-256-cbc",
      passphrase: PASSPHRASE,
    },
  });

/** Encrypts a request for a legacy session as base64. */
export const encrypt = (data: unknown, deviceKey: TapoDeviceKey): string => {
  const cipher = crypto.createCipheriv(
    AES_CIPHER_ALGORITHM,
    deviceKey.key,
    deviceKey.iv,
  );
  const ciphertext = cipher.update(Buffer.from(JSON.stringify(data)));
  return Buffer.concat([ciphertext, cipher.final()]).toString("base64");
};

/**
 * Decrypts a legacy session response. Content that does not decrypt or is not JSON throws a
 * SyntaxError.
 */
export const decrypt = (data: string, deviceKey: TapoDeviceKey): unknown =>
  readDecryptedJson(() => {
    const cipher = crypto.createDecipheriv(
      AES_CIPHER_ALGORITHM,
      deviceKey.key,
      deviceKey.iv,
    );
    const ciphertext = cipher.update(Buffer.from(data, "base64"));
    return Buffer.concat([ciphertext, cipher.final()]);
  });

/**
 * Decrypts the session key a device sent in its legacy handshake. Throws when the key does not
 * decrypt, and on Node versions that refuse RSA PKCS#1 v1.5 padding for private decryption.
 */
export const readDeviceKey = (pemKey: string, privateKey: string): Buffer =>
  crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PADDING,
      passphrase: PASSPHRASE,
    },
    Buffer.from(pemKey, "base64"),
  );

/** Encodes text as base64. */
export const base64Encode = (data: string): string =>
  Buffer.from(data).toString("base64");

/** Decodes base64 to text, with empty input decoding to an empty string. */
export const base64Decode = (data: string): string => {
  if (!data) return "";
  return Buffer.from(data, "base64").toString();
};

/** Hashes text with SHA-1 as hex. */
export const shaDigest = (data: string): string =>
  crypto.createHash("sha1").update(data).digest("hex");
