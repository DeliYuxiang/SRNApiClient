/**
 * SRN Protocol — Ed25519 signing and verification primitives.
 *
 * Mirrors Go srn/event.go exactly:
 *   - canonicalTagsFor: excludes source_type/source_uri, sorts by tag[0]
 *   - canonicalJSON: JSON.stringify (no HTML escaping — Go uses SetEscapeHTML(false))
 *   - computeID: SHA256(canonicalJSON) → full 64 hex chars (V2)
 *   - signEvent: computes ID, signs canonicalJSON bytes with Ed25519 private key
 *   - verifyEvent: recomputes ID and verifies signature
 */

export function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const arr = new Uint8Array(hex.length >> 1);
  for (let i = 0; i < hex.length; i += 2) {
    arr[i >> 1] = parseInt(hex.slice(i, i + 2), 16);
  }
  return arr;
}

export function bytesToHex(buf: ArrayBuffer | Uint8Array): string {
  return Array.from(new Uint8Array(buf instanceof Uint8Array ? buf.buffer : buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Filter and sort tags for canonical signing.
 * Rules (must match Go canonicalTagsFor):
 *   - Exclude source_type and source_uri (internal provenance)
 *   - Sort ascending by tag name (tag[0]) for determinism
 */
export function canonicalTagsFor(tags: string[][]): string[][] {
  return tags
    .filter((t) => t.length >= 1 && t[0] !== "source_type" && t[0] !== "source_uri")
    .sort((a, b) => (a[0]! < b[0]! ? -1 : a[0]! > b[0]! ? 1 : 0));
}

/**
 * Produce the canonical JSON string for an event's identity fields.
 * Format: JSON([pubkey, kind, canonical_tags, content_md5])
 *
 * JS JSON.stringify does not escape '<', '>', '&' by default — this matches
 * Go's json.Encoder with SetEscapeHTML(false).
 */
export function canonicalJSON(
  pubkey: string,
  kind: number,
  tags: string[][],
  contentMd5: string,
): string {
  return JSON.stringify([pubkey, kind, canonicalTagsFor(tags), contentMd5]);
}

/**
 * Compute the event ID as the full SHA256 of the canonical JSON (64 hex chars, V2).
 * Matches Go ComputeIDV2().
 */
export async function computeID(
  pubkey: string,
  kind: number,
  tags: string[][],
  contentMd5: string,
): Promise<string> {
  const msg = canonicalJSON(pubkey, kind, tags, contentMd5);
  const hashBuf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(msg),
  );
  return bytesToHex(hashBuf);
}

export interface SignInput {
  pubkey: string;
  kind: number;
  tags: string[][];
  contentMd5: string;
}

/**
 * Sign an event.
 *
 * @param fields   Event identity fields
 * @param privKeyHex  Ed25519 private key as PKCS8 hex (format used by srnfrontend)
 * @returns { id, sig } — 64-hex ID and hex-encoded Ed25519 signature
 */
export async function signEvent(
  fields: SignInput,
  privKeyHex: string,
): Promise<{ id: string; sig: string }> {
  const { pubkey, kind, tags, contentMd5 } = fields;
  const msg = canonicalJSON(pubkey, kind, tags, contentMd5);
  const msgBytes = new TextEncoder().encode(msg);

  const privKey = await crypto.subtle.importKey(
    "pkcs8",
    hexToBytes(privKeyHex),
    { name: "Ed25519" },
    false,
    ["sign"],
  );

  const sigBuf = await crypto.subtle.sign("Ed25519", privKey, msgBytes);
  const id = bytesToHex(
    await crypto.subtle.digest("SHA-256", msgBytes),
  );

  return { id, sig: bytesToHex(sigBuf) };
}

export interface VerifyInput extends SignInput {
  id: string;
  sig: string;
}

export interface VerifyResult {
  /** Whether the recomputed ID matches the stored ID. */
  idMatch: boolean;
  /**
   * If idMatch is false, indicates whether the stored ID matches the V1
   * format (SHA256[:16], 32 hex chars) used by Go Sign(). Helpful for
   * diagnosing V1 vs V2 mismatches in existing production data.
   */
  idMatchV1: boolean;
  /** Whether the Ed25519 signature is valid over the canonical message. */
  sigValid: boolean;
}

/**
 * Verify an event's ID and signature.
 *
 * The ID check is against the V2 format (64 hex chars). idMatchV1 is also
 * populated to help detect events signed with the older Go Sign() which
 * used the V1 truncated format (32 hex chars).
 *
 * Signature verification is independent of the ID format.
 */
export async function verifyEvent(event: VerifyInput): Promise<VerifyResult> {
  const { pubkey, kind, tags, contentMd5, id, sig } = event;
  const msg = canonicalJSON(pubkey, kind, tags, contentMd5);
  const msgBytes = new TextEncoder().encode(msg);

  const hashBuf = await crypto.subtle.digest("SHA-256", msgBytes);
  const hashBytes = new Uint8Array(hashBuf);

  const idV2 = bytesToHex(hashBuf);
  const idV1 = bytesToHex(hashBytes.slice(0, 16)); // Go Sign() truncated form

  const idMatch = id === idV2;
  const idMatchV1 = !idMatch && id === idV1;

  let sigValid = false;
  try {
    const pubKeyObj = await crypto.subtle.importKey(
      "raw",
      hexToBytes(pubkey),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    sigValid = await crypto.subtle.verify(
      "Ed25519",
      pubKeyObj,
      hexToBytes(sig),
      msgBytes,
    );
  } catch {
    sigValid = false;
  }

  return { idMatch, idMatchV1, sigValid };
}

/**
 * Verify a raw Ed25519 signature over an arbitrary message string.
 * Used by the relay worker to verify signed requests.
 */
export async function verifySignature(
  pubKeyHex: string,
  sigHex: string,
  message: string,
): Promise<boolean> {
  try {
    const pubKey = await crypto.subtle.importKey(
      "raw",
      hexToBytes(pubKeyHex),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      "Ed25519",
      pubKey,
      hexToBytes(sigHex),
      new TextEncoder().encode(message),
    );
  } catch {
    return false;
  }
}

/** Generate a new Ed25519 keypair. Returns keys as hex strings. */
export async function generateKeypair(): Promise<{
  pubHex: string;
  privHex: string;
}> {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
  ]);
  const pubBuf = await crypto.subtle.exportKey("raw", kp.publicKey);
  const privBuf = await crypto.subtle.exportKey("pkcs8", kp.privateKey);
  return { pubHex: bytesToHex(pubBuf), privHex: bytesToHex(privBuf) };
}
