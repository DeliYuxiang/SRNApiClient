package srn

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// Event is the atomic unit of the Subtitle Relay Network.
// It follows the "Dumb Relays, Smart Clients" philosophy.
type Event struct {
	ID         string     `json:"id"`          // 64 hex chars, full sha256 fingerprint (V2)
	PubKey     string     `json:"pubkey"`      // Ed25519 public key (hex)
	CreatedAt  int64      `json:"created_at"`  // Unix timestamp (set by relay on receipt)
	Kind       int        `json:"kind"`        // 1001 = subtitle
	Tags       [][]string `json:"tags"`        // [["tmdb","123"],["language","zh"],["s","1"],["e","1"]]
	ContentMD5 string     `json:"content_md5"` // MD5 hex of subtitle file content
	Sig        string     `json:"sig"`         // Ed25519 signature (see relay.go for wire protocol)
	// Optional/Internal
	Filename string `json:"filename,omitempty"` // for local recognition only
}

// UnmarshalJSON handles two wire formats for Tags:
//   - Native JSON array:  "tags": [["tmdb","123"],["s","1"]]     (local / future relays)
//   - JSON-encoded string: "tags": "[[\"tmdb\",\"123\"],[\"s\",\"1\"]]"  (current CF worker)
//
// All other fields are decoded normally.
func (e *Event) UnmarshalJSON(data []byte) error {
	type wireEvent struct {
		ID         string          `json:"id"`
		PubKey     string          `json:"pubkey"`
		CreatedAt  int64           `json:"created_at"`
		Kind       int             `json:"kind"`
		Tags       json.RawMessage `json:"tags"`
		ContentMD5 string          `json:"content_md5"`
		Sig        string          `json:"sig"`
		Filename   string          `json:"filename,omitempty"`
	}
	var w wireEvent
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	e.ID = w.ID
	e.PubKey = w.PubKey
	e.CreatedAt = w.CreatedAt
	e.Kind = w.Kind
	e.ContentMD5 = w.ContentMD5
	e.Sig = w.Sig
	e.Filename = w.Filename

	if len(w.Tags) == 0 || string(w.Tags) == "null" {
		return nil
	}
	// Try native [][]string first.
	if err := json.Unmarshal(w.Tags, &e.Tags); err == nil {
		return nil
	}
	// Fall back: relay serialised tags as a JSON string containing the array.
	var s string
	if err := json.Unmarshal(w.Tags, &s); err != nil {
		return fmt.Errorf("srn: cannot parse tags field: %w", err)
	}
	return json.Unmarshal([]byte(s), &e.Tags)
}

// GetTag returns the value of the first tag with the given name.
func (e *Event) GetTag(name string) string {
	for _, t := range e.Tags {
		if len(t) >= 2 && t[0] == name {
			return t[1]
		}
	}
	return ""
}

const (
	KindSubtitle    = 1001
	KindRetract     = 1002
	KindReplace     = 1003
	KindKeyAlias    = 1011
	KindBulkSalvage = 1020
	KindDegradation = 1031 // reserved for relay-to-client degradation notifications
)

// NewRetractEvent creates a Kind 1002 event to deactivate targetID.
func NewRetractEvent(pubkey, targetID, reason string) *Event {
	return &Event{
		PubKey: pubkey,
		Kind:   KindRetract,
		Tags: [][]string{
			{"e", targetID},
			{"reason", reason},
		},
		ContentMD5: "",
	}
}

// NewReplaceEvent creates a Kind 1003 event replacing prevID with new content.
func NewReplaceEvent(pubkey, prevID string, tags [][]string, contentMD5 string) *Event {
	// Ensure "e" tag is present
	hasE := false
	for _, t := range tags {
		if len(t) >= 2 && t[0] == "e" {
			hasE = true
			break
		}
	}
	if !hasE {
		tags = append([][]string{{"e", prevID}}, tags...)
	}

	return &Event{
		PubKey:     pubkey,
		Kind:       KindReplace,
		Tags:       tags,
		ContentMD5: contentMD5,
	}
}

// NewKeyAliasEvent creates a Kind 1011 event declaring a human-readable alias.
func NewKeyAliasEvent(pubkey, alias, url, about string) *Event {
	return &Event{
		PubKey: pubkey,
		Kind:   KindKeyAlias,
		Tags: [][]string{
			{"alias", alias},
			{"url", url},
			{"about", about},
		},
		ContentMD5: "",
	}
}

// NewBulkSalvageEvent creates a Kind 1020 event to permanently remove deactivated events.
func NewBulkSalvageEvent(pubkey string, targetIDs []string) *Event {
	tags := make([][]string, 0, len(targetIDs))
	for _, id := range targetIDs {
		tags = append(tags, []string{"e", id})
	}
	return &Event{
		PubKey:     pubkey,
		Kind:       KindBulkSalvage,
		Tags:       tags,
		ContentMD5: "",
	}
}

// canonicalTagsFor returns a filtered, sorted copy of tags suitable for canonical signing.
// Rules:
//   - source_type and source_uri are excluded (internal provenance, not part of protocol identity)
//   - remaining tags are sorted ascending by tag name (tag[0]) for determinism
//
// This produces the same output regardless of original tag insertion order,
// enabling interoperability with any client that builds tags independently.
func canonicalTagsFor(tags [][]string) [][]string {
	out := make([][]string, 0, len(tags))
	for _, t := range tags {
		if len(t) >= 1 && (t[0] == "source_uri" || t[0] == "source_type") {
			continue
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}

// canonicalJSON encodes v to JSON with HTML escaping disabled.
// HTML escaping must be off so that '<', '>', '&' are not rewritten to
// \u003c / \u003e / \u0026 — TypeScript's JSON.stringify does not escape these,
// so the byte sequences must match on both sides.
func canonicalJSON(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// canonicalHash encodes the event's identity fields as canonical JSON and
// returns the resulting SHA256 digest. All callers (ComputeID, ComputeIDV2,
// Sign) share this single computation path.
func (e *Event) canonicalHash() ([32]byte, []byte) {
	data, _ := canonicalJSON([]interface{}{e.PubKey, e.Kind, canonicalTagsFor(e.Tags), e.ContentMD5})
	return sha256.Sum256(data), data
}

// ComputeID returns the V1 truncated fingerprint (32 hex chars, SHA256[:16]).
// Deprecated: use ComputeIDV2 for new events. Retained for reading legacy records.
func (e *Event) ComputeID() string {
	h, _ := e.canonicalHash()
	return hex.EncodeToString(h[:16]) // 32 hex chars — V1 truncated form
}

// ComputeIDV2 returns the full SHA256 fingerprint (64 hex chars) of the event.
// V2 uses the complete 32-byte hash; the canonical input is identical to V1.
func (e *Event) ComputeIDV2() string {
	h, _ := e.canonicalHash()
	return hex.EncodeToString(h[:])
}

// Sign computes the V2 event ID (full SHA256, 64 hex chars) and signs the
// canonical message with the private key.
// Canonical message: JSON([pubkey, kind, canonical_tags, content_md5])
// Same form used by relay.go PublishToNetwork and verified by the SRN relay worker.
func (e *Event) Sign(priv ed25519.PrivateKey) error {
	h, data := e.canonicalHash()
	e.ID = hex.EncodeToString(h[:]) // V2: full SHA256, 64 hex chars
	e.Sig = hex.EncodeToString(ed25519.Sign(priv, data))
	return nil
}

// Verify checks the ID and signature against the canonical message.
// Accepts both V2 (64 hex) and legacy V1 (32 hex) IDs so that records
// written before the migration can still be verified.
func (e *Event) Verify() bool {
	if e.ID != e.ComputeIDV2() && e.ID != e.ComputeID() {
		return false
	}
	pubKeyBytes, err := hex.DecodeString(e.PubKey)
	if err != nil {
		return false
	}
	sigBytes, err := hex.DecodeString(e.Sig)
	if err != nil {
		return false
	}
	canonical := []interface{}{e.PubKey, e.Kind, canonicalTagsFor(e.Tags), e.ContentMD5}
	data, _ := canonicalJSON(canonical)
	return ed25519.Verify(pubKeyBytes, data, sigBytes)
}
