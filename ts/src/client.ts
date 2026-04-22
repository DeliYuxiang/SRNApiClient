/**
 * SRN API Client — framework-agnostic.
 *
 * Mirrors the logic in srnfrontend/src/lib/apiClient.ts and
 * srnfrontend/src/composables/useSRNClient.ts, but expressed as a plain class
 * rather than Vue composables.  Works in Node.js 22+, browsers, and Cloudflare
 * Workers (anywhere WebCrypto + fetch are available).
 */

import { hexToBytes, bytesToHex } from "./crypto.js";
import { mineNonce } from "./pow.js";
import type {
  Identity,
  ChallengeParams,
  SRNEvent,
  TMDBResult,
  EventsQuery,
} from "./types.js";

// ─── Auth helpers ─────────────────────────────────────────────────────────────

/**
 * Import an Ed25519 PKCS8 private key from hex.
 *
 * Matches srnfrontend/src/composables/useIdentity.ts importPrivKey.
 */
export async function importPrivKey(privHex: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "pkcs8",
    hexToBytes(privHex).buffer as ArrayBuffer,
    { name: "Ed25519" },
    false,
    ["sign"],
  );
}

/**
 * Sign a UTF-8 message with an Ed25519 private key and return the three
 * X-SRN-* auth headers.
 *
 * Matches srnfrontend/src/lib/apiClient.ts buildAuthHeaders.
 */
export async function buildAuthHeaders(
  pubHex: string,
  privKey: CryptoKey,
  nonce: string,
  message: string,
): Promise<Record<string, string>> {
  const sigBuf = await crypto.subtle.sign(
    "Ed25519",
    privKey,
    new TextEncoder().encode(message),
  );
  return {
    "X-SRN-PubKey": pubHex,
    "X-SRN-Nonce": nonce,
    "X-SRN-Signature": bytesToHex(sigBuf),
  };
}

/**
 * Fetch PoW challenge parameters from the relay.
 * Optionally supplies X-SRN-PubKey so the relay can give a VIP k=0 response.
 */
export async function fetchChallenge(
  baseUrl: string,
  pubHex?: string,
): Promise<ChallengeParams> {
  const headers: Record<string, string> = pubHex
    ? { "X-SRN-PubKey": pubHex }
    : {};
  const res = await fetch(`${baseUrl}/v1/challenge`, { headers });
  return res.json() as Promise<ChallengeParams>;
}

// ─── Raw-event → SRNEvent mapper ──────────────────────────────────────────────

type RawEvent = Record<string, unknown>;

/** Parse the raw API event (tags as JSON string) into the typed SRNEvent. */
function mapEvent(e: RawEvent): SRNEvent {
  return {
    id: e.id as string,
    pubkey: e.pubkey as string,
    kind: e.kind as number,
    content_md5: e.content_md5 as string,
    tags:
      typeof e.tags === "string"
        ? (JSON.parse(e.tags) as string[][])
        : (e.tags as string[][]),
    sig: e.sig as string,
    created_at: e.created_at as number,
    // API returns tmdb_id as string (query-param coercion); normalise to number.
    tmdb_id: e.tmdb_id != null ? Number(e.tmdb_id) : 0,
    season_num: (e.season_num as number | null | undefined) ?? null,
    episode_num: (e.episode_num as number | null | undefined) ?? null,
    language: (e.language as string | null | undefined) ?? null,
    archive_md5: (e.archive_md5 as string | null | undefined) ?? null,
    source_type: (e.source_type as string | null | undefined) ?? null,
    source_uri: (e.source_uri as string | null | undefined) ?? null,
    filename: e.filename as string | undefined,
  };
}

// ─── SRNClient ────────────────────────────────────────────────────────────────

/**
 * Stateful SRN API client.
 *
 * Manages one Ed25519 identity and a refreshable PoW session.  All protected
 * endpoints inject auth headers automatically and retry once on 401/403.
 *
 * Usage:
 *   const client = new SRNClient("https://relay.example.com", identity);
 *   await client.init();                       // import key + mine first nonce
 *   const events = await client.searchEvents({ tmdb: "12345" });
 */
export class SRNClient {
  private readonly baseUrl: string;
  private readonly identity: Identity;
  private privKey: CryptoKey | null = null;
  private nonce = "0";

  constructor(baseUrl: string, identity: Identity) {
    this.baseUrl = baseUrl;
    this.identity = identity;
  }

  /**
   * Import the private key and mine an initial PoW nonce.
   * Must be called once before any API request.
   */
  async init(): Promise<void> {
    this.privKey = await importPrivKey(this.identity.privHex);
    await this.refreshChallenge();
  }

  /** Fetch a fresh challenge and mine a new nonce. */
  async refreshChallenge(): Promise<void> {
    const params = await fetchChallenge(this.baseUrl, this.identity.pubHex);
    this.nonce = await mineNonce(params.salt, this.identity.pubHex, params.k);
  }

  private async authHeaders(message: string): Promise<Record<string, string>> {
    if (!this.privKey) throw new Error("SRNClient not initialised — call init() first");
    return buildAuthHeaders(this.identity.pubHex, this.privKey, this.nonce, message);
  }

  /**
   * Run a fetch; on 401/403 refresh the PoW challenge and retry once.
   *
   * @param url        Full request URL.
   * @param init       Function that receives the auth headers and returns RequestInit.
   * @param getMessage Returns the message to sign — called lazily on each attempt
   *                   so download requests can recompute the current UTC minute.
   */
  private async withRetry(
    url: string,
    init: (headers: Record<string, string>) => RequestInit,
    getMessage: () => string,
  ): Promise<Response> {
    const doFetch = async () => {
      const headers = await this.authHeaders(getMessage());
      return fetch(url, init(headers));
    };

    let res = await doFetch();
    if (res.status === 401 || res.status === 403) {
      await this.refreshChallenge();
      res = await doFetch();
    }
    return res;
  }

  /** Search subtitle events. All query params are optional. */
  async searchEvents(query: EventsQuery = {}): Promise<SRNEvent[]> {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(query)) {
      if (v != null) params.set(k, String(v));
    }
    const qs = params.size ? `?${params}` : "";
    const res = await this.withRetry(
      `${this.baseUrl}/v1/events${qs}`,
      (headers) => ({ headers }),
      () => this.identity.pubHex,
    );
    const data = (await res.json()) as { events: RawEvent[] };
    return (data.events ?? []).map(mapEvent);
  }

  /** Search TMDB for a title. */
  async searchTMDB(q: string, fresh?: boolean): Promise<TMDBResult[]> {
    const params = new URLSearchParams({ q });
    if (fresh) params.set("fresh", "1");
    const res = await this.withRetry(
      `${this.baseUrl}/v1/tmdb/search?${params}`,
      (headers) => ({ headers }),
      () => this.identity.pubHex,
    );
    const data = (await res.json()) as { results: TMDBResult[] };
    return data.results ?? [];
  }

  /**
   * Fetch the episode count for a TMDB season.
   * Returns null when the relay doesn't have the data or the request fails.
   */
  async getSeasonInfo(tmdbId: number, season: number): Promise<number | null> {
    const params = new URLSearchParams({
      tmdb_id: String(tmdbId),
      season: String(season),
    });
    const res = await this.withRetry(
      `${this.baseUrl}/v1/tmdb/season?${params}`,
      (headers) => ({ headers }),
      () => this.identity.pubHex,
    );
    if (!res.ok) return null;
    const data = (await res.json()) as { episode_count: number };
    return data.episode_count ?? null;
  }

  /**
   * Download a subtitle file by event ID.
   *
   * Uses time-based signing (current UTC minute) to prevent replay attacks,
   * matching the server's verifyDownloadRequest logic.
   *
   * @returns Raw binary content of the subtitle file.
   */
  async downloadContent(eventId: string): Promise<Uint8Array> {
    const res = await this.withRetry(
      `${this.baseUrl}/v1/events/${eventId}/content`,
      (headers) => ({ headers }),
      // Recomputed on each attempt in case we cross a minute boundary during retry.
      () => String(Math.floor(Date.now() / 60000)),
    );
    return new Uint8Array(await res.arrayBuffer());
  }
}
