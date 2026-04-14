/**
 * Ergo Schnorr proveDlog proof verification — pure TypeScript port of
 * sigma-rust's `ergotree-interpreter::verifier::verify_signature` for a single
 * ProveDlog leaf (P2PK).
 *
 * Matches Nautilus `sign_data` output under the EIP-0044 ADH message format.
 *
 * SPECIAL: P10 — any divergence from sigma-rust's algorithm is a potential
 * auth bypass. The regression tests in `schnorr.test.ts` enshrine a captured
 * Nautilus signature as the canonical positive vector.
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { blake2b } from "@noble/hashes/blake2b";
import { timingSafeEqual } from "node:crypto";

const CHALLENGE_BYTES = 24;
const RESPONSE_BYTES = 32;
export const PROOF_BYTES = CHALLENGE_BYTES + RESPONSE_BYTES; // 56 bytes = 112 hex
const PUBKEY_BYTES = 33;

// EIP-0044 ADH prefixes: [invalidator_byte, network_byte]
const MAINNET_PREFIX = new Uint8Array([0x00, 0x00]);
const TESTNET_PREFIX = new Uint8Array([0x00, 0x10]);

function bytesToBigInt(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

/**
 * Fiat-Shamir pre-image for a single ProveDlog leaf, matching sigma-rust's
 * `fiat_shamir_tree_to_bytes`:
 *
 *   LEAF_PREFIX (1 byte = 0x01)
 *   prop_len    (2 bytes, i16 big-endian, always 0x00 0x27 for P2PK)
 *   prop_bytes  (39 bytes: ErgoTree v0 w/ constants-segregated encoding
 *                SigmaProp(ProveDlog(pk)) — layout below)
 *   commit_len  (2 bytes, i16 big-endian, always 0x00 0x21)
 *   commit      (33-byte compressed EC point `a`)
 *
 * P2PK prop_bytes (fixed 39 bytes): 0x10 0x01 0x08 0xcd <33-byte pk> 0x73 0x00
 */
function fiatShamirTreeBytes(pubKey: Uint8Array, aCompressed: Uint8Array): Uint8Array {
  const propBytes = new Uint8Array([
    0x10, 0x01, 0x08, 0xcd,
    ...pubKey,
    0x73, 0x00,
  ]);
  return new Uint8Array([
    0x01,
    (propBytes.length >> 8) & 0xff, propBytes.length & 0xff,
    ...propBytes,
    (aCompressed.length >> 8) & 0xff, aCompressed.length & 0xff,
    ...aCompressed,
  ]);
}

/**
 * Verify an Ergo Schnorr proveDlog proof.
 *
 * Proof layout: challenge (24 bytes) || response z (32 bytes).
 * Message is hashed as EIP-0044 ADH: `[0x00, network, blake2b256(utf8)]`.
 *
 * Algorithm:
 *   1. Parse challenge `e` and response `z` from proof.
 *   2. Reconstruct commitment `a = z*G − e*P`. Schnorr uses z = r + xe so
 *      verification g^z = a·h^e rearranges to a = g^z / h^e, i.e. subtract
 *      in additive EC. (Note: `+e*P` is the common textbook error.)
 *   3. Serialize Fiat-Shamir tree: LEAF_PREFIX || prop_len || prop_bytes ||
 *      commit_len || a_compressed.
 *   4. Recompute e' = blake2b256(tree_bytes || signed_msg)[0..24].
 *   5. Accept if e == e' under mainnet prefix (tried first — Fleet SDK
 *      defaults to mainnet even for testnet addresses) or testnet.
 *
 * @returns null on success, error string on failure.
 */
export function verifySchnorrProof(
  proofHex: string,
  publicKeyHex: string,
  message: string,
): string | null {
  let proofBytes: Buffer;
  let pubKeyBytes: Buffer;
  try {
    proofBytes = Buffer.from(proofHex, "hex");
    pubKeyBytes = Buffer.from(publicKeyHex, "hex");
  } catch {
    return "invalid hex in proof or public key";
  }

  if (proofBytes.length !== PROOF_BYTES) {
    return `proof must be ${PROOF_BYTES} bytes (${PROOF_BYTES * 2} hex), got ${proofBytes.length}`;
  }
  if (pubKeyBytes.length !== PUBKEY_BYTES) {
    return `public key must be ${PUBKEY_BYTES} bytes, got ${pubKeyBytes.length}`;
  }

  const challenge = proofBytes.slice(0, CHALLENGE_BYTES);
  const zBytes = proofBytes.slice(CHALLENGE_BYTES);

  const msgHash = blake2b(Buffer.from(message, "utf8"), { dkLen: 32 });

  let P: InstanceType<typeof secp256k1.ProjectivePoint>;
  try {
    P = secp256k1.ProjectivePoint.fromHex(pubKeyBytes);
  } catch {
    return "invalid secp256k1 public key";
  }

  const z = bytesToBigInt(new Uint8Array(zBytes));
  const e = bytesToBigInt(new Uint8Array(challenge));

  let aCompressed: Uint8Array;
  try {
    const G = secp256k1.ProjectivePoint.BASE;
    const aPoint = G.multiply(z).add(P.multiply(e).negate());
    aCompressed = aPoint.toRawBytes(true);
  } catch {
    return "EC point arithmetic failed";
  }

  const treeBytes = fiatShamirTreeBytes(new Uint8Array(pubKeyBytes), aCompressed);

  for (const prefix of [MAINNET_PREFIX, TESTNET_PREFIX]) {
    const signedMsg = new Uint8Array([...prefix, ...msgHash]);
    const hashInput = new Uint8Array([...treeBytes, ...signedMsg]);
    const ePrime = blake2b(hashInput, { dkLen: 32 }).slice(0, CHALLENGE_BYTES);
    if (timingSafeEqual(Buffer.from(challenge), Buffer.from(ePrime))) {
      return null;
    }
  }
  return "Schnorr signature verification failed";
}
