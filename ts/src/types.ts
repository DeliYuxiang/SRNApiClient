/**
 * Core SRN protocol types shared between the API client and any consumer.
 *
 * These are framework-agnostic (no Vue, no React) and mirror the types in
 * srnfrontend/src/types/api.ts, consolidated here as the single source of
 * truth for the @srn/client package.
 */

/** Ed25519 keypair stored as PKCS8 hex (private) and raw hex (public). */
export interface Identity {
  pubHex: string;
  privHex: string; // PKCS8-encoded Ed25519 private key, hex-encoded
}

/** PoW challenge parameters returned by GET /v1/challenge. */
export interface ChallengeParams {
  salt: string; // hex HMAC salt tied to IP and time window
  k: number; // leading zero hex chars required
  vip: boolean; // VIPs get k=0
}

/** A fully-decoded SRN event (tags parsed from JSON string). */
export interface SRNEvent {
  id: string;
  pubkey: string;
  kind: number;
  content_md5: string;
  tags: string[][];
  sig: string;
  created_at: number;
  tmdb_id: number;
  season_num: number | null;
  episode_num: number | null;
  language: string | null;
  archive_md5: string | null;
  source_type: string | null;
  source_uri: string | null;
  filename?: string;
}

/** TMDB search result shape. */
export interface TMDBResult {
  id: number;
  name?: string;
  title?: string;
  poster_path: string | null;
  media_type: "tv" | "movie";
  first_air_date?: string;
  release_date?: string;
}

/** Query parameters accepted by GET /v1/events. */
export interface EventsQuery {
  tmdb?: string;
  season?: string;
  ep?: string;
  language?: string;
  kind?: string;
  pubkey?: string;
  archive_md5?: string;
}
