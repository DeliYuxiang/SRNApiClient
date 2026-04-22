/**
 * SRN Protocol — Proof-of-Work primitives.
 *
 * Mirrors Go srn/relay.go mineNonce and worker verify-pubkey.ts verifyPoW.
 *
 * Algorithm: find nonce N such that
 *   hex(SHA256(salt + pubKeyHex + N)).startsWith("0".repeat(k))
 */

import { bytesToHex } from "./crypto.js";

const encoder = new TextEncoder();

/**
 * Mine a PoW nonce.
 *
 * Differences from existing implementations:
 *   - Go caps at 5_000_000 iterations and returns "0" on timeout.
 *     This implementation matches the Go cap for consistency in tests.
 *   - srnfrontend pow.worker.ts has no cap (runs until found).
 *
 * @param salt             Hex HMAC salt from GET /v1/challenge
 * @param pubHex           Client Ed25519 public key (hex)
 * @param k                Number of leading zero hex chars required
 * @param maxIter          Iteration cap (default 5_000_000, matches Go)
 * @param onProgress       Optional callback fired every `progressInterval` iterations
 * @param progressInterval How often to fire onProgress (default 500)
 * @returns The nonce string, or "0" if cap is reached without a solution
 */
export async function mineNonce(
  salt: string,
  pubHex: string,
  k: number,
  maxIter = 5_000_000,
  onProgress?: (attempts: number) => void,
  progressInterval = 500,
): Promise<string> {
  if (k <= 0) return "0";

  const prefix = "0".repeat(k);
  for (let i = 0; i <= maxIter; i++) {
    const nonce = String(i);
    const hashBuf = await crypto.subtle.digest(
      "SHA-256",
      encoder.encode(salt + pubHex + nonce),
    );
    if (bytesToHex(hashBuf).startsWith(prefix)) return nonce;
    if (onProgress && i > 0 && i % progressInterval === 0) onProgress(i);
  }
  return "0"; // cap reached, triggers a challenge refresh on retry
}

/**
 * Verify a PoW nonce.
 * Mirrors worker/src/lib/verify-pubkey.ts verifyPoW exactly.
 */
export async function verifyPoW(
  pubKeyHex: string,
  nonce: string,
  difficulty: number,
  salt: string,
): Promise<boolean> {
  if (difficulty <= 0) return true;
  const hashBuf = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(salt + pubKeyHex + nonce),
  );
  return bytesToHex(hashBuf).startsWith("0".repeat(difficulty));
}
