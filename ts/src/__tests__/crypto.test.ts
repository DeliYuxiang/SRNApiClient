import { describe, it, expect } from "vitest";
import {
  generateKeypair,
  signEvent,
  verifyEvent,
  verifySignature,
  canonicalTagsFor,
  canonicalJSON,
  computeID,
} from "../crypto.js";

describe("canonicalTagsFor", () => {
  it("excludes source_type and source_uri", () => {
    const tags = [
      ["tmdb", "123"],
      ["source_type", "opensubtitles"],
      ["language", "zh"],
      ["source_uri", "https://example.com"],
    ];
    const result = canonicalTagsFor(tags);
    expect(result).toEqual([
      ["language", "zh"],
      ["tmdb", "123"],
    ]);
  });

  it("sorts by tag name ascending", () => {
    const tags = [
      ["s", "1"],
      ["e", "abc"],
      ["language", "zh"],
      ["tmdb", "123"],
    ];
    expect(canonicalTagsFor(tags).map((t) => t[0])).toEqual([
      "e",
      "language",
      "s",
      "tmdb",
    ]);
  });

  it("is stable for already-sorted tags", () => {
    const tags = [["a", "1"], ["b", "2"], ["c", "3"]];
    expect(canonicalTagsFor(tags)).toEqual(tags);
  });
});

describe("canonicalJSON", () => {
  it("matches Go SetEscapeHTML(false) — angle brackets not escaped", () => {
    const tags = [["note", "<test>"]];
    const json = canonicalJSON("pubkey", 1001, tags, "md5");
    expect(json).toContain("<test>");
    expect(json).not.toContain("\\u003c");
  });

  it("produces deterministic output regardless of input tag order", () => {
    const tags1 = [["tmdb", "123"], ["language", "zh"]];
    const tags2 = [["language", "zh"], ["tmdb", "123"]];
    expect(canonicalJSON("pk", 1001, tags1, "md5")).toBe(
      canonicalJSON("pk", 1001, tags2, "md5"),
    );
  });
});

describe("sign → verify round-trip", () => {
  it("sign then verifyEvent returns idMatch=true and sigValid=true", async () => {
    const { pubHex, privHex } = await generateKeypair();
    const fields = {
      pubkey: pubHex,
      kind: 1001,
      tags: [["tmdb", "12345"], ["language", "zh-CN"], ["s", "1"], ["e", "3"]],
      contentMd5: "d41d8cd98f00b204e9800998ecf8427e",
    };

    const { id, sig } = await signEvent(fields, privHex);

    // ID should be 64 hex chars (V2)
    expect(id).toHaveLength(64);
    expect(id).toMatch(/^[0-9a-f]+$/);

    const result = await verifyEvent({ ...fields, id, sig });
    expect(result.idMatch).toBe(true);
    expect(result.idMatchV1).toBe(false);
    expect(result.sigValid).toBe(true);
  });

  it("tampered content_md5 invalidates signature", async () => {
    const { pubHex, privHex } = await generateKeypair();
    const fields = {
      pubkey: pubHex,
      kind: 1001,
      tags: [["tmdb", "999"]],
      contentMd5: "aabbcc",
    };

    const { id, sig } = await signEvent(fields, privHex);
    const result = await verifyEvent({
      ...fields,
      contentMd5: "000000", // tampered
      id,
      sig,
    });
    expect(result.sigValid).toBe(false);
  });

  it("tampered id is caught by idMatch", async () => {
    const { pubHex, privHex } = await generateKeypair();
    const fields = {
      pubkey: pubHex,
      kind: 1001,
      tags: [],
      contentMd5: "",
    };
    const { id, sig } = await signEvent(fields, privHex);
    const result = await verifyEvent({
      ...fields,
      id: id.replace(/^../, "ff"), // tamper first 2 chars
      sig,
    });
    expect(result.idMatch).toBe(false);
    // Signature should still be valid (sign is over canonicalJSON, not id)
    expect(result.sigValid).toBe(true);
  });
});

describe("verifySignature", () => {
  it("verifies a raw message signature", async () => {
    const { pubHex, privHex } = await generateKeypair();
    const { signEvent: _unused, ..._ } = await import("../crypto.js");

    // Sign pubHex directly (same pattern as GET /v1/events auth)
    const privKey = await crypto.subtle.importKey(
      "pkcs8",
      new Uint8Array(privHex.match(/.{1,2}/g)!.map((b) => parseInt(b, 16))),
      { name: "Ed25519" },
      false,
      ["sign"],
    );
    const sigBuf = await crypto.subtle.sign(
      "Ed25519",
      privKey,
      new TextEncoder().encode(pubHex),
    );
    const sigHex = Array.from(new Uint8Array(sigBuf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    expect(await verifySignature(pubHex, sigHex, pubHex)).toBe(true);
    expect(await verifySignature(pubHex, sigHex, "wrong-message")).toBe(false);
  });
});

describe("computeID", () => {
  it("matches signEvent id", async () => {
    const { pubHex, privHex } = await generateKeypair();
    const fields = {
      pubkey: pubHex,
      kind: 1001,
      tags: [["tmdb", "42"]],
      contentMd5: "deadbeef",
    };
    const { id } = await signEvent(fields, privHex);
    const computed = await computeID(
      fields.pubkey,
      fields.kind,
      fields.tags,
      fields.contentMd5,
    );
    expect(computed).toBe(id);
  });
});
