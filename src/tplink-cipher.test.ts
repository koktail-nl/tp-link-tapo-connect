import { base64Decode, base64Encode, shaDigest } from "./tplink-cipher";

it("text survives a base64 round trip", () => {
  expect(base64Decode(base64Encode("user@example.com"))).toBe(
    "user@example.com",
  );
});

it("empty base64 decodes to an empty string", () => {
  expect(base64Decode("")).toBe("");
});

it("a SHA-1 digest is hex", () => {
  expect(shaDigest("abc")).toBe("a9993e364706816aba3e25717850c26c9cd0d89d");
});
