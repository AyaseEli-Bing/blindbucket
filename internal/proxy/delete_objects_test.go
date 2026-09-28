package proxy

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// postDelete sends a DeleteObjects body and returns the status and response.
func (h *harness) postDelete(t *testing.T, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		h.proxy.URL+"/"+testBucket+"?delete", strings.NewReader(body))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, readBody(t, resp)
}

func deleteBody(keys ...string) string {
	var b strings.Builder
	b.WriteString("<Delete>")
	for _, key := range keys {
		b.WriteString("<Object><Key>" + key + "</Key></Object>")
	}
	b.WriteString("</Delete>")
	return b.String()
}

// TestIntegrationDeleteObjectsUnderEncryptedNames: the client names its own
// keys, the provider only knows the encrypted ones, and the answer has to come
// back in the client's names -- or a client matching the Deleted list against
// what it asked for would believe nothing was deleted.
func TestIntegrationDeleteObjectsUnderEncryptedNames(t *testing.T) {
	option, enc := withEncryptedNames(t)
	h := newHarness(t, option)
	prefix := fmt.Sprintf("bulk-delete-names/%d/", time.Now().UnixNano())
	keys := []string{prefix + "one", prefix + "two"}
	for _, key := range keys {
		stored, err := enc.EncryptKey(key)
		if err != nil {
			t.Fatalf("EncryptKey: %v", err)
		}
		h.cleanupStored(t, stored)
		resp := h.put(t, key, []byte("payload"), nil)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PUT %s: %d", key, resp.StatusCode)
		}
	}

	status, body := h.postDelete(t, deleteBody(keys...))
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	var result upstream.DeleteResult
	if err := xml.Unmarshal([]byte(body), &result); err != nil {
		t.Fatalf("parsing: %v\n%s", err, body)
	}
	got := map[string]bool{}
	for _, d := range result.Deleted {
		got[d.Key] = true
	}
	for _, key := range keys {
		if !got[key] {
			t.Errorf("%s is not reported deleted under its own name; the answer was:\n%s", key, body)
		}
		stored, _ := enc.EncryptKey(key)
		if _, err := h.upstream.HeadObject(context.Background(), testBucket, stored); !upstream.NotFound(err) {
			t.Errorf("%s survived the bulk delete", key)
		}
	}
}

func TestIntegrationDeleteObjectsRefusesMalformedBodies(t *testing.T) {
	h := newHarness(t)
	for name, body := range map[string]string{
		"not XML":            "this is not a delete request",
		"no objects in it":   "<Delete><Quiet>true</Quiet></Delete>",
		"an unclosed object": "<Delete><Object><Key>a</Key>",
	} {
		t.Run(name, func(t *testing.T) {
			if status, resp := h.postDelete(t, body); status != http.StatusBadRequest {
				t.Errorf("status %d, want 400: %s", status, resp)
			}
		})
	}
}
