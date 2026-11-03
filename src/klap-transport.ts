import axios from "axios";
import {
  createCipheriv,
  randomBytes,
  createHash,
  createDecipheriv,
} from "crypto";
import { TapoDevice } from "./tapo-device";
import { checkError } from "./tapo-utils";
import {
  deviceHttp,
  readDecryptedJson,
  readDeviceResponse,
  readSessionCookie,
} from "./device-http";

// Typescript port of https://gist.github.com/chriswheeldon/3b17d974db3817613c69191c0480fe55

const AES_CIPHER_ALGORITHM = "aes-128-cbc";
const SEED_LENGTH = 16;
const KEY_LENGTH = 16;
const SIGNATURE_LENGTH = 28;
const SHA256_LENGTH = 32;
const IV_PREFIX_LENGTH = 12;
const SEQ_LENGTH = 4;
// The device finalizes a new session shortly after handshake2.
const SESSION_SETTLE_MS = 100;

/**
 * Logs in to a device over the KLAP protocol.
 *
 * Throws `Klap protocol not supported` when the device has no KLAP endpoint (404),
 * `Invalid credentials - device rejected authentication` when it refuses the handshake (403),
 * `email or password incorrect` when its hash matches neither the email nor its lower case,
 * `handshake1 failed: ...` or `handshake2 failed: ...` for any other failed or unanswered handshake
 * (with the request error as cause, or `response too short`), and
 * `Device response carries no session cookie` when the device sets no session.
 */
export const loginDeviceByIp = async (
  email: string,
  password: string,
  deviceIp: string,
): Promise<ReturnType<typeof TapoDevice>> => {
  // handshake1
  const localSeed = randomBytes(SEED_LENGTH);

  const response = await deviceHttp
    .post<ArrayBuffer>(`http://${deviceIp}/app/handshake1`, localSeed, {
      responseType: "arraybuffer",
      withCredentials: true,
    })
    .catch((error: unknown) => {
      const status = readStatus(error);
      if (status === 404) {
        throw new Error(`Klap protocol not supported`);
      }
      if (status === 403) {
        throw new Error(`Invalid credentials - device rejected authentication`);
      }
      throw new Error(`handshake1 failed: ${error}`, { cause: error });
    });

  const responseBytes = Buffer.from(response.data);
  if (responseBytes.length < SEED_LENGTH + SHA256_LENGTH) {
    throw new Error("handshake1 failed: response too short");
  }
  const sessionCookie = readSessionCookie(response.headers);

  const remoteSeed = responseBytes.subarray(0, SEED_LENGTH);
  const serverHash = responseBytes.subarray(SEED_LENGTH);

  // A device can derive its login hash from the account email in lower case, while the cloud
  // login accepts the email in any casing, so the email matches as given or in lower case.
  const localAuthHash = [email, email.toLowerCase()]
    .map((candidate) => generateAuthHash(candidate, password))
    .find((authHash) =>
      compare(handshake1AuthHash(localSeed, remoteSeed, authHash), serverHash),
    );

  if (!localAuthHash) {
    throw new Error("email or password incorrect");
  }

  // handshake2
  const payload = handshake2AuthHash(localSeed, remoteSeed, localAuthHash);
  await deviceHttp
    .post(`http://${deviceIp}/app/handshake2`, payload, {
      responseType: "arraybuffer",
      headers: {
        Cookie: sessionCookie,
      },
    })
    .catch((error: unknown) => {
      throw new Error(`handshake2 failed: ${error}`, { cause: error });
    });

  await new Promise((resolve) => setTimeout(resolve, SESSION_SETTLE_MS));

  return createKlapEncryptionSession(
    deviceIp,
    localSeed,
    remoteSeed,
    localAuthHash,
    sessionCookie,
  );
};

const createKlapEncryptionSession = (
  deviceIp: string,
  localSeed: Buffer,
  remoteSeed: Buffer,
  userHash: Buffer,
  sessionCookie: string,
) => {
  const key = deriveKey(localSeed, remoteSeed, userHash);
  const iv = deriveIv(localSeed, remoteSeed, userHash);
  const sig = deriveSig(localSeed, remoteSeed, userHash);

  let seq = deriveSeqFromIv(iv);

  const encrypt = (payload: unknown, requestSeq: Buffer) => {
    const payloadJson = JSON.stringify(payload);
    const cipher = createCipheriv(
      AES_CIPHER_ALGORITHM,
      key,
      ivWithSeq(iv, requestSeq),
    );
    const ciphertext = cipher.update(encode(payloadJson));
    return Buffer.concat([ciphertext, cipher.final()]);
  };

  const decrypt = (payload: Buffer, requestSeq: Buffer): unknown =>
    readDecryptedJson(() => {
      const cipher = createDecipheriv(
        AES_CIPHER_ALGORITHM,
        key,
        ivWithSeq(iv, requestSeq),
      );
      const ciphertext = cipher.update(payload.subarray(SHA256_LENGTH));
      return Buffer.concat([ciphertext, cipher.final()]);
    });

  const encryptAndSign = (payload: unknown, requestSeq: Buffer) => {
    const ciphertext = encrypt(payload, requestSeq);
    const signature = sha256(Buffer.concat([sig, requestSeq, ciphertext]));
    return Buffer.concat([signature, ciphertext]);
  };

  // A failed request rejects with the axios error, which carries the network code or HTTP status.
  // A response that does not decrypt to JSON rejects with a SyntaxError.
  const send = async (deviceRequest: unknown): Promise<unknown> => {
    seq = incrementSeq(seq);
    const requestSeq = Buffer.from(seq);

    const encryptedRequest = encryptAndSign(deviceRequest, requestSeq);

    const response = await deviceHttp.request<ArrayBuffer>({
      method: "post",
      url: `http://${deviceIp}/app/request`,
      data: encryptedRequest,
      responseType: "arraybuffer",
      headers: {
        Cookie: sessionCookie,
      },
      params: {
        seq: requestSeq.readInt32BE(),
      },
    });

    const decryptedResponse = readDeviceResponse(
      decrypt(Buffer.from(response.data), requestSeq),
    );
    checkError(decryptedResponse);
    return decryptedResponse.result;
  };

  return TapoDevice({ send });
};

/** Thrown by consumers for a device that speaks neither KLAP nor the legacy protocol. */
export class ProtocolUnsupportedError extends Error {
  readonly type = "ProtocolUnsupportedError" as const;
}

const readStatus = (error: unknown): unknown =>
  axios.isAxiosError(error) ? error.response?.status : undefined;

const handshake1AuthHash = (
  localSeed: Buffer,
  remoteSeed: Buffer,
  authHash: Buffer,
) => sha256(Buffer.concat([localSeed, remoteSeed, authHash]));

const handshake2AuthHash = (
  localSeed: Buffer,
  remoteSeed: Buffer,
  authHash: Buffer,
) => sha256(Buffer.concat([remoteSeed, localSeed, authHash]));

const generateAuthHash = (email: string, password: string) =>
  sha256(Buffer.concat([sha1(email), sha1(password)]));

const deriveKey = (localSeed: Buffer, remoteSeed: Buffer, userHash: Buffer) =>
  sha256(
    Buffer.concat([encode("lsk"), localSeed, remoteSeed, userHash]),
  ).subarray(0, KEY_LENGTH);

const deriveIv = (localSeed: Buffer, remoteSeed: Buffer, userHash: Buffer) =>
  sha256(Buffer.concat([encode("iv"), localSeed, remoteSeed, userHash]));

const deriveSig = (localSeed: Buffer, remoteSeed: Buffer, userHash: Buffer) =>
  sha256(
    Buffer.concat([encode("ldk"), localSeed, remoteSeed, userHash]),
  ).subarray(0, SIGNATURE_LENGTH);

const deriveSeqFromIv = (iv: Buffer) => iv.subarray(iv.length - SEQ_LENGTH);

const ivWithSeq = (iv: Buffer, seq: Buffer) =>
  Buffer.concat([iv.subarray(0, IV_PREFIX_LENGTH), seq]);

const incrementSeq = (seq: Buffer) => {
  const buffer = Buffer.alloc(SEQ_LENGTH);
  buffer.writeInt32BE(seq.readInt32BE() + 1);
  return buffer;
};

const sha256 = (data: string | Buffer) =>
  createHash("sha256").update(data).digest();

const sha1 = (data: string | Buffer) =>
  createHash("sha1").update(data).digest();

const compare = (b1: Buffer, b2: Buffer) => b1.compare(b2) === 0;

const encode = (text: string) => Buffer.from(text, "utf-8");
