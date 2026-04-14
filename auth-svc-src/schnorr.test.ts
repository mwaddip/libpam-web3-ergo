import { test } from "node:test";
import assert from "node:assert/strict";
import { verifySchnorrProof } from "./schnorr";

/**
 * Captured from a real Nautilus sign_data session during login to a
 * provisioned testnet VM. The wallet is testnet (address prefix '3') but
 * Fleet SDK's ErgoMessage.fromData() defaults to mainnet prefix, so the
 * signed message is [0x00, 0x00, blake2b256(msg_utf8)].
 *
 * Independently verified against sigma-rust's verify_signature.
 */
const VECTOR = {
  signature:
    "2f007062d92faea2c77ae85758999262e856ce737495f9eb74ab33e26903c9d084a5544209d31500917c390452d56d889fae680a408d4a96",
  public_key:
    "0347203530f6977e33b0465a0da69428f2497f90ce32434fc16fb17c93e3e8300e",
  message: "Authenticate to blockhost-001 with code: 145553",
};

test("accepts captured Nautilus mainnet-prefix signature", () => {
  assert.equal(
    verifySchnorrProof(VECTOR.signature, VECTOR.public_key, VECTOR.message),
    null,
  );
});

test("rejects signature with mutated last byte", () => {
  const last = VECTOR.signature.slice(-2);
  const flipped = ((parseInt(last, 16) ^ 0x01) & 0xff).toString(16).padStart(2, "0");
  const tampered = VECTOR.signature.slice(0, -2) + flipped;
  assert.equal(tampered.length, VECTOR.signature.length);
  assert.equal(
    verifySchnorrProof(tampered, VECTOR.public_key, VECTOR.message),
    "Schnorr signature verification failed",
  );
});

test("rejects signature against a different message", () => {
  assert.equal(
    verifySchnorrProof(VECTOR.signature, VECTOR.public_key, "different"),
    "Schnorr signature verification failed",
  );
});

test("rejects signature against a different valid pubkey", () => {
  // Flip the compression-byte parity — still a valid compressed point, but
  // decodes to a different EC point.
  const wrongKey = "02" + VECTOR.public_key.slice(2);
  assert.equal(
    verifySchnorrProof(VECTOR.signature, wrongKey, VECTOR.message),
    "Schnorr signature verification failed",
  );
});

test("rejects wrong-length proof", () => {
  const err = verifySchnorrProof(
    "00".repeat(55),
    VECTOR.public_key,
    VECTOR.message,
  );
  assert.match(err ?? "", /proof must be 56 bytes/);
});

test("rejects wrong-length pubkey", () => {
  const err = verifySchnorrProof(
    VECTOR.signature,
    "00".repeat(32),
    VECTOR.message,
  );
  assert.match(err ?? "", /public key must be 33 bytes/);
});
