package srn

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrPermanentUpload is returned when an upload failure cannot be fixed by retrying
// (HTTP 4xx other than 429 Too Many Requests).
type ErrPermanentUpload struct {
	StatusCode int
	Body       string
}

func (e *ErrPermanentUpload) Error() string {
	return fmt.Sprintf("status %d: %s", e.StatusCode, e.Body)
}

var relayHTTPClient = &http.Client{Timeout: 30 * time.Second}

type nonceInfo struct {
	Nonce string
	Salt  string
}

var (
	nonceCache   = make(map[string]*nonceInfo)
	nonceCacheMu sync.RWMutex
)

func mineNonce(salt, pubkey string, k int) string {
	if k <= 0 {
		return "0"
	}
	prefix := strings.Repeat("0", k)
	for i := 0; ; i++ {
		nonce := strconv.Itoa(i)
		h := sha256.New()
		h.Write([]byte(salt))
		h.Write([]byte(pubkey))
		h.Write([]byte(nonce))
		hash := hex.EncodeToString(h.Sum(nil))
		if strings.HasPrefix(hash, prefix) {
			return nonce
		}
		if i > 5000000 {
			return "0"
		}
	}
}

func fetchChallenge(relayURL, pubkey string) (*ChallengeResponse, error) {
	client, err := NewClientWithResponses(relayURL, WithHTTPClient(relayHTTPClient))
	if err != nil {
		return nil, err
	}
	resp, err := client.GetV1ChallengeWithResponse(context.Background(),
		func(_ context.Context, req *http.Request) error {
			if pubkey != "" {
				req.Header.Set("X-SRN-PubKey", pubkey)
			}
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() != 200 || resp.JSON200 == nil {
		return nil, fmt.Errorf("challenge status %d", resp.StatusCode())
	}
	return resp.JSON200, nil
}

func ensureNonce(relayURL, pubkey string) string {
	nonceCacheMu.RLock()
	n, ok := nonceCache[relayURL]
	nonceCacheMu.RUnlock()
	if ok {
		return n.Nonce
	}
	ci, err := fetchChallenge(relayURL, pubkey)
	if err != nil {
		slog.Default().Error("❌ [SRN] 获取挑战失败", "relay", relayURL, "err", err)
		return "0"
	}
	nonce := mineNonce(ci.Salt, pubkey, ci.K)
	nonceCacheMu.Lock()
	nonceCache[relayURL] = &nonceInfo{Nonce: nonce, Salt: ci.Salt}
	nonceCacheMu.Unlock()
	return nonce
}

func refreshNonceFromError(relayURL, pubHex string, errResp *ErrorResponse) {
	if errResp == nil || errResp.Challenge == nil {
		nonceCacheMu.Lock()
		delete(nonceCache, relayURL)
		nonceCacheMu.Unlock()
		return
	}
	c := errResp.Challenge
	nonce := mineNonce(c.Salt, pubHex, c.K)
	nonceCacheMu.Lock()
	nonceCache[relayURL] = &nonceInfo{Nonce: nonce, Salt: c.Salt}
	nonceCacheMu.Unlock()
}

var (
	nodeGETMu   sync.RWMutex
	nodePubHex  string
	nodePrivKey ed25519.PrivateKey
	nodeGETSig  string
)

// SetNodeKey registers the node's Ed25519 identity key for signing outbound requests.
func SetNodeKey(priv ed25519.PrivateKey) {
	if priv == nil {
		return
	}
	pub := priv.Public().(ed25519.PublicKey)
	pubHex := hex.EncodeToString(pub)
	sig := ed25519.Sign(priv, []byte(pubHex))
	nodeGETMu.Lock()
	nodePubHex = pubHex
	nodePrivKey = priv
	nodeGETSig = hex.EncodeToString(sig)
	nodeGETMu.Unlock()
}

func makeAuthEditor(relayURL string) RequestEditorFn {
	return func(_ context.Context, req *http.Request) error {
		nodeGETMu.RLock()
		pub, priv, sig := nodePubHex, nodePrivKey, nodeGETSig
		nodeGETMu.RUnlock()
		if pub == "" {
			return nil
		}
		nonce := ensureNonce(relayURL, pub)
		req.Header.Set("X-SRN-PubKey", pub)
		req.Header.Set("X-SRN-Nonce", nonce)
		if strings.HasSuffix(req.URL.Path, "/content") {
			minute := strconv.FormatInt(time.Now().Unix()/60, 10)
			sig = hex.EncodeToString(ed25519.Sign(priv, []byte(minute)))
		}
		req.Header.Set("X-SRN-Signature", sig)
		return nil
	}
}

func newRelayClient(relayURL string) (*ClientWithResponses, error) {
	return NewClientWithResponses(relayURL,
		WithHTTPClient(relayHTTPClient),
		WithRequestEditorFn(makeAuthEditor(relayURL)),
	)
}

func srnEventToEvent(se SRNEvent) Event {
	e := Event{
		ID:         se.Id,
		PubKey:     se.Pubkey,
		CreatedAt:  int64(se.CreatedAt),
		Kind:       se.Kind,
		ContentMD5: se.ContentMd5,
		Sig:        se.Sig,
	}
	if se.Tags != "" {
		_ = json.Unmarshal([]byte(se.Tags), &e.Tags)
	}
	return e
}

func strPtr(s string) *string { return &s }

func truncateBody(b []byte, maxLen int) string {
	if len(b) <= maxLen {
		return string(b)
	}
	return string(b[:maxLen]) + "…"
}

// QueryRelay searches a single relay. Use QueryNetwork for multi-relay fan-out.
func QueryRelay(relayURL, tmdbID, lang string, season, ep int) ([]Event, error) {
	params := &GetV1EventsParams{Kind: strPtr("1001")}
	if tmdbID != "" {
		params.Tmdb = strPtr(tmdbID)
	}
	if lang != "" {
		params.Language = strPtr(lang)
	}
	// season=0 is valid (OVA/specials); always include season when ep is present
	// because the relay requires season whenever ep is specified (Zod validation).
	if ep > 0 {
		params.Season = strPtr(strconv.Itoa(season))
		params.Ep = strPtr(strconv.Itoa(ep))
	} else if season > 0 {
		params.Season = strPtr(strconv.Itoa(season))
	}

	client, err := newRelayClient(relayURL)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := client.GetV1EventsWithResponse(ctx, params)
	if err != nil {
		return nil, err
	}

	if s := resp.StatusCode(); s == 400 || s == 401 || s == 403 {
		nodeGETMu.RLock()
		pub := nodePubHex
		nodeGETMu.RUnlock()

		var errResp *ErrorResponse
		switch s {
		case 401:
			errResp = resp.JSON401
		case 403:
			errResp = resp.JSON403
		case 400:
			// relay may return 400 with an embedded challenge when nonce is stale
			var er ErrorResponse
			if json.Unmarshal(resp.Body, &er) == nil && er.Challenge != nil {
				errResp = &er
			}
		}
		slog.Default().Warn("🔑 [SRN] GET /v1/events → auth error, refreshing PoW",
			"relay", relayURL, "status", s)
		refreshNonceFromError(relayURL, pub, errResp)
		resp, err = client.GetV1EventsWithResponse(ctx, params)
		if err != nil {
			return nil, err
		}
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode(), truncateBody(resp.Body, 300))
	}
	if resp.JSON200 == nil {
		return nil, fmt.Errorf("empty response")
	}

	events := make([]Event, 0, len(resp.JSON200.Events))
	for _, se := range resp.JSON200.Events {
		events = append(events, srnEventToEvent(se))
	}
	return events, nil
}

// MergeEvents appends events from source into target, deduplicating by ID.
func MergeEvents(target *[]Event, source []Event) {
	seen := make(map[string]struct{}, len(*target))
	for _, t := range *target {
		seen[t.ID] = struct{}{}
	}
	for _, s := range source {
		if _, ok := seen[s.ID]; !ok {
			*target = append(*target, s)
		}
	}
}

// QueryNetwork searches all relays for subtitles matching the given criteria.
func QueryNetwork(relayURLs []string, tmdbID, lang string, season, ep int) []Event {
	if len(relayURLs) == 0 {
		return nil
	}
	var mu sync.Mutex
	var allEvents []Event
	var wg sync.WaitGroup
	for _, rURL := range relayURLs {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			events, err := QueryRelay(u, tmdbID, lang, season, ep)
			if err != nil {
				slog.Default().Error("❌ [SRN] Query failed", "relay", u, "err", err)
				return
			}
			mu.Lock()
			MergeEvents(&allEvents, events)
			mu.Unlock()
		}(rURL)
	}
	wg.Wait()
	return allEvents
}

// QueryNetworkForLangs queries all relays for each language, deduplicating results.
// An empty langs slice queries for all events (no language filter).
func QueryNetworkForLangs(relayURLs []string, tmdbID string, langs []string, season, ep int) []Event {
	if len(langs) == 1 {
		return QueryNetwork(relayURLs, tmdbID, langs[0], season, ep)
	}
	var all []Event
	for _, lang := range langs {
		evs := QueryNetwork(relayURLs, tmdbID, lang, season, ep)
		MergeEvents(&all, evs)
	}
	return all
}

// RelayIdentity represents the metadata of an SRN relay.
type RelayIdentity struct {
	PubKey      string `json:"pubkey"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

// QueryRelayIdentity fetches the identity of a relay.
func QueryRelayIdentity(relayURL string) (*RelayIdentity, error) {
	resp, err := relayHTTPClient.Get(fmt.Sprintf("%s/v1/identity", relayURL))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var identity RelayIdentity
	if err := json.NewDecoder(resp.Body).Decode(&identity); err != nil {
		return nil, err
	}
	return &identity, nil
}

// publishPayload is the wire format sent to the relay as the `event` multipart field.
type publishPayload struct {
	ID         string     `json:"id"`
	PubKey     string     `json:"pubkey"`
	Kind       int        `json:"kind"`
	Tags       [][]string `json:"tags"`
	ContentMD5 string     `json:"content_md5"`
	Filename   string     `json:"filename,omitempty"`
	TmdbID     string     `json:"tmdb_id,omitempty"`
	SeasonNum  int        `json:"season_num,omitempty"`
	EpisodeNum int        `json:"episode_num,omitempty"`
	Language   string     `json:"language,omitempty"`
	ArchiveMD5 string     `json:"archive_md5,omitempty"`
	SourceType string     `json:"source_type,omitempty"`
	SourceURI  string     `json:"source_uri,omitempty"`
}

// PublishToNetwork signs and broadcasts an event to all relays in relayURLs.
func PublishToNetwork(relayURLs []string, ev *Event, data []byte, privKey ed25519.PrivateKey) error {
	if len(relayURLs) == 0 {
		return fmt.Errorf("no relays configured")
	}

	if data != nil && ev.ContentMD5 == "" {
		ev.ContentMD5 = fmt.Sprintf("%x", md5.Sum(data))
	}
	ev.CreatedAt = time.Now().Unix()
	ev.PubKey = hex.EncodeToString(privKey.Public().(ed25519.PublicKey))
	ev.ID = ev.ComputeIDV2()

	payload := &publishPayload{
		ID:         ev.ID,
		PubKey:     ev.PubKey,
		Kind:       ev.Kind,
		Tags:       ev.Tags,
		ContentMD5: ev.ContentMD5,
		Filename:   ev.Filename,
		TmdbID:     ev.GetTag("tmdb"),
		Language:   ev.GetTag("language"),
		ArchiveMD5: ev.GetTag("archive_md5"),
		SourceType: ev.GetTag("source_type"),
		SourceURI:  ev.GetTag("source_uri"),
	}
	if s, err := strconv.Atoi(ev.GetTag("s")); err == nil {
		payload.SeasonNum = s
	}
	if e, err := strconv.Atoi(ev.GetTag("e")); err == nil {
		payload.EpisodeNum = e
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal failed: %v", err)
	}

	canonicalMsg, err := canonicalJSON([]interface{}{ev.PubKey, ev.Kind, canonicalTagsFor(ev.Tags), ev.ContentMD5})
	if err != nil {
		return fmt.Errorf("canonical marshal failed: %v", err)
	}
	sig := ed25519.Sign(privKey, canonicalMsg)
	sigHex := hex.EncodeToString(sig)
	ev.Sig = sigHex

	var mu sync.Mutex
	var errs []error
	successes := 0
	var wg sync.WaitGroup
	for _, rURL := range relayURLs {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			if err := pushToOneRelay(u, ev.PubKey, sigHex, payloadJSON, ev.Filename, data); err != nil {
				slog.Default().Error("❌ [SRN] Push failed", "relay", u, "err", err)
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			} else {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}(rURL)
	}
	wg.Wait()

	if successes > 0 {
		return nil
	}
	if len(errs) == 0 {
		return nil
	}
	allPermanent := true
	for _, err := range errs {
		var pe *ErrPermanentUpload
		if !errors.As(err, &pe) {
			allPermanent = false
			break
		}
	}
	if allPermanent {
		return errs[0]
	}
	return fmt.Errorf("%d relay(s) failed: %w", len(errs), errs[0])
}

// RetractEvent publishes a Kind 1002 retraction to all relays.
func RetractEvent(relayURLs []string, targetID, reason string, privKey ed25519.PrivateKey) error {
	pubkey := hex.EncodeToString(privKey.Public().(ed25519.PublicKey))
	ev := NewRetractEvent(pubkey, targetID, reason)
	return PublishToNetwork(relayURLs, ev, nil, privKey)
}

// ReplaceEvent publishes a Kind 1003 replacement to all relays.
func ReplaceEvent(relayURLs []string, prevID string, tags [][]string, data []byte, filename string, privKey ed25519.PrivateKey) error {
	pubkey := hex.EncodeToString(privKey.Public().(ed25519.PublicKey))
	contentMD5 := fmt.Sprintf("%x", md5.Sum(data))
	ev := NewReplaceEvent(pubkey, prevID, tags, contentMD5)
	ev.Filename = filename
	return PublishToNetwork(relayURLs, ev, data, privKey)
}

func pushToOneRelay(relayURL, pubKeyHex, sigHex string, payloadJSON []byte, filename string, data []byte) error {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	_ = writer.WriteField("event", string(payloadJSON))
	part, _ := writer.CreateFormFile("file", filename)
	if data == nil {
		data = []byte{}
	}
	_, _ = io.Copy(part, bytes.NewReader(data))
	writer.Close()

	nonce := ensureNonce(relayURL, pubKeyHex)
	client, err := NewClientWithResponses(relayURL, WithHTTPClient(relayHTTPClient))
	if err != nil {
		return err
	}
	postAuth := func(_ context.Context, req *http.Request) error {
		req.Header.Set("X-SRN-PubKey", pubKeyHex)
		req.Header.Set("X-SRN-Nonce", nonce)
		req.Header.Set("X-SRN-Signature", sigHex)
		return nil
	}
	ctx := context.Background()
	resp, err := client.PostV1EventsWithBodyWithResponse(ctx, &PostV1EventsParams{},
		writer.FormDataContentType(), bytes.NewReader(body.Bytes()), postAuth)
	if err != nil {
		return err
	}
	if resp.StatusCode() >= 400 {
		if resp.StatusCode() == 401 || resp.StatusCode() == 403 {
			var errResp *ErrorResponse
			if resp.JSON401 != nil {
				errResp = resp.JSON401
			} else if resp.JSON403 != nil {
				errResp = resp.JSON403
			}
			refreshNonceFromError(relayURL, pubKeyHex, errResp)
			return fmt.Errorf("auth %d", resp.StatusCode())
		}
		if resp.StatusCode() != http.StatusTooManyRequests && resp.StatusCode() < 500 {
			errMsg := ""
			if resp.JSON400 != nil {
				errMsg = resp.JSON400.Error
			}
			return &ErrPermanentUpload{StatusCode: resp.StatusCode(), Body: errMsg}
		}
		return fmt.Errorf("status %d", resp.StatusCode())
	}
	return nil
}

// DownloadFromRelays fetches subtitle content by event ID, trying each relay in order.
func DownloadFromRelays(relayURLs []string, id string) ([]byte, error) {
	for _, u := range relayURLs {
		client, err := newRelayClient(u)
		if err != nil {
			continue
		}
		ctx := context.Background()
		resp, err := client.GetV1EventsIdContentWithResponse(ctx, id, &GetV1EventsIdContentParams{})
		if err != nil {
			continue
		}
		if s := resp.StatusCode(); s == 401 || s == 403 {
			nodeGETMu.RLock()
			pub := nodePubHex
			nodeGETMu.RUnlock()
			var errResp *ErrorResponse
			if resp.JSON401 != nil {
				errResp = resp.JSON401
			} else if resp.JSON403 != nil {
				errResp = resp.JSON403
			}
			refreshNonceFromError(u, pub, errResp)
			resp, err = client.GetV1EventsIdContentWithResponse(ctx, id, &GetV1EventsIdContentParams{})
			if err != nil {
				continue
			}
		}
		if resp.StatusCode() == http.StatusOK {
			return resp.Body, nil
		}
	}
	return nil, fmt.Errorf("not found on any relay")
}
