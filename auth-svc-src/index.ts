/**
 * web3-auth-svc — Ergo auth service for libpam-web3.
 *
 * Self-contained HTTPS server: HTTP boilerplate (routes, TLS, body limits,
 * slowloris timeout, signal handling) is in auth-svc-common; this file
 * provides only the Ergo-specific Schnorr verification + .sig writer.
 *
 * .sig file format (JSON):
 *   { chain: "ergo", signature, public_key, otp, machine_id }
 *
 * SPECIAL profile: S8 P10 E7 C5 I8 A8 L7
 *   P10: Auth boundary — validate every input, trust nothing from the network.
 *   E7: Long-running daemon — must not crash, must not leak.
 *
 * Cryptographic verification:
 *   Schnorr proveDlog proof verified in `schnorr.ts` against the EIP-0044 ADH
 *   message format. This is a safety check — the PAM plugin independently
 *   derives the address from the pubkey.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { timingSafeEqual } from "node:crypto";
import {
  runServer,
  type CallbackError,
} from "../../../auth-svc-common/server";
import { verifySchnorrProof } from "./schnorr";
import { chainPort } from "./chain-port";

const CHAIN_NAME = "ergo";

// Schnorr proof + 33-byte compressed pubkey, hex-encoded — fits in <1.5KB.
const MAX_BODY_SIZE = 1500;

const HEX_RE = /^[0-9a-fA-F]+$/;

function isValidHex(str: string): boolean {
  return str.length > 0 && str.length % 2 === 0 && HEX_RE.test(str);
}

interface CallbackPayload {
  signature: string;
  key: string;
  otp: string;
  machineId: string;
}

function parseCallbackBody(body: string): CallbackPayload | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return null;
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return null;
  }

  const obj = parsed as Record<string, unknown>;
  const keys = Object.keys(obj);

  if (keys.length !== 4) return null;
  if (typeof obj["signature"] !== "string") return null;
  if (typeof obj["key"] !== "string") return null;
  if (typeof obj["otp"] !== "string") return null;
  if (typeof obj["machineId"] !== "string") return null;

  if (obj["otp"].length > 16 || obj["machineId"].length > 128) return null;

  if (!isValidHex(obj["signature"])) return null;
  if (!isValidHex(obj["key"])) return null;

  return {
    signature: obj["signature"],
    key: obj["key"],
    otp: obj["otp"],
    machineId: obj["machineId"],
  };
}

interface SessionData {
  otp: string;
  machine_id: string;
}

function readSession(sessionId: string, pendingDir: string): SessionData | null {
  const jsonPath = path.join(pendingDir, `${sessionId}.json`);
  try {
    const content = fs.readFileSync(jsonPath, "utf8");
    const parsed: unknown = JSON.parse(content);
    if (typeof parsed !== "object" || parsed === null) return null;
    const obj = parsed as Record<string, unknown>;
    if (typeof obj["otp"] !== "string" || typeof obj["machine_id"] !== "string") {
      return null;
    }
    return { otp: obj["otp"], machine_id: obj["machine_id"] };
  } catch {
    return null;
  }
}

interface ErgoSigFile {
  chain: "ergo";
  signature: string;
  public_key: string;
  otp: string;
  machine_id: string;
}

function handleCallback(
  sessionId: string,
  body: string,
  pendingDir: string,
): CallbackError | null {
  const payload = parseCallbackBody(body);
  if (!payload) return { kind: "invalid", message: "invalid request body" };

  const sigPath = path.join(pendingDir, `${sessionId}.sig`);
  if (fs.existsSync(sigPath)) return { kind: "conflict" };

  const session = readSession(sessionId, pendingDir);
  if (!session) return { kind: "not-found" };

  const otpA = Buffer.from(payload.otp);
  const otpB = Buffer.from(session.otp);
  if (otpA.length !== otpB.length || !timingSafeEqual(otpA, otpB)) {
    return { kind: "invalid", message: "otp mismatch" };
  }
  if (payload.machineId !== session.machine_id) {
    return { kind: "invalid", message: "machine_id mismatch" };
  }

  // Public key: must be 33 bytes (66 hex chars), compressed secp256k1
  if (payload.key.length !== 66) {
    return {
      kind: "invalid",
      message: `public key must be 33 bytes (66 hex), got ${payload.key.length} hex chars`,
    };
  }
  const keyPrefix = payload.key.slice(0, 2).toLowerCase();
  if (keyPrefix !== "02" && keyPrefix !== "03") {
    return {
      kind: "invalid",
      message: `invalid compressed pubkey prefix: ${keyPrefix} (expected 02 or 03)`,
    };
  }

  // Verify Schnorr proveDlog proof.
  const message = `Authenticate to ${payload.machineId} with code: ${payload.otp}`;
  const verifyErr = verifySchnorrProof(payload.signature, payload.key, message);
  if (verifyErr) return { kind: "invalid", message: verifyErr };

  const sigContent: ErgoSigFile = {
    chain: "ergo",
    signature: payload.signature,
    public_key: payload.key,
    otp: payload.otp,
    machine_id: payload.machineId,
  };

  const tmpPath = path.join(pendingDir, `${sessionId}.sig.tmp`);
  try {
    fs.writeFileSync(tmpPath, JSON.stringify(sigContent));
    fs.renameSync(tmpPath, sigPath);
  } catch (err) {
    try { fs.unlinkSync(tmpPath); } catch { /* tmp may not exist */ }
    return {
      kind: "invalid",
      message: `sig file write failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  console.log(`[AUTH] Verified Schnorr proof for session ${sessionId}`);
  return null;
}

// Only run as a server when invoked as the entry point. Test imports skip.
if (process.argv[1]?.match(/\/(auth-svc\.js|index\.ts)$/)) {
  runServer({
    chain: CHAIN_NAME,
    defaultPort: chainPort(CHAIN_NAME),
    maxBodySize: MAX_BODY_SIZE,
    requireJson: true,
    requestTimeoutMs: 5000,
    handleCallback,
  });
}
