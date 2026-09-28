package objectmeta

import (
	"errors"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
)

func sample(t *testing.T, multipart bool) Meta {
	t.Helper()
	m := Meta{
		Version:       stream.Version,
		KeyID:         "2026-09",
		WrappedDEK:    make([]byte, keys.WrappedDEKSize),
		Log2ChunkSize: stream.DefaultLog2ChunkSize,
		HasChunkSize:  true,
	}
	for i := range m.WrappedDEK {
		m.WrappedDEK[i] = byte(i)
	}
	if multipart {
		id, err := manifest.NewID()
		if err != nil {
			t.Fatalf("NewID: %v", err)
		}
		m.ManifestID, m.Multipart = id, true
	}
	return m
}

func TestHeadersRoundTrip(t *testing.T) {
	for _, multipart := range []bool{false, true} {
		want := sample(t, multipart)
		got, err := Parse(want.Headers(), 0)
		if err != nil {
			t.Fatalf("multipart=%t: %v", multipart, err)
		}
		if got.KeyID != want.KeyID || string(got.WrappedDEK) != string(want.WrappedDEK) ||
			got.Log2ChunkSize != want.Log2ChunkSize || !got.HasChunkSize ||
			got.Multipart != multipart || got.ManifestID != want.ManifestID {
			t.Errorf("multipart=%t: got %+v, want %+v", multipart, got, want)
		}
	}
}

// TestParseReadsWhatProvidersSend: S3 hands user metadata back with whatever
// casing it chose, and a gateway that only matched its own would find nothing.
func TestParseReadsWhatProvidersSend(t *testing.T) {
	headers := sample(t, false).Headers()
	shouted := map[string]string{}
	for k, v := range headers {
		shouted[strings.ToUpper(k)] = v
	}
	if _, err := Parse(shouted, 0); err != nil {
		t.Errorf("upper-cased metadata was not read: %v", err)
	}
}

func TestParseFallsBackToTheConfiguredChunkSize(t *testing.T) {
	headers := sample(t, false).Headers()
	delete(headers, metaChunkSize)
	got, err := Parse(headers, 20)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Log2ChunkSize != 20 || got.HasChunkSize {
		t.Errorf("got chunk size 2^%d (recorded %t), want the fallback 2^20", got.Log2ChunkSize, got.HasChunkSize)
	}
}

// TestParseRefusesWhatAProviderCouldForge: metadata is the provider's to
// return, and every field is read by code that must not trust it.
func TestParseRefusesWhatAProviderCouldForge(t *testing.T) {
	if _, err := Parse(map[string]string{"content-type": "text/plain"}, 16); !errors.Is(err, ErrNotEncrypted) {
		t.Errorf("an object without a wrapped key: got %v, want ErrNotEncrypted", err)
	}

	for name, edit := range map[string]func(map[string]string){
		"no version":             func(h map[string]string) { delete(h, metaVersion) },
		"a version from later":   func(h map[string]string) { h[metaVersion] = "2" },
		"a key id with a slash":  func(h map[string]string) { h[metaKeyID] = "../etc" },
		"no key id":              func(h map[string]string) { delete(h, metaKeyID) },
		"a wrapped key not b64":  func(h map[string]string) { h[metaDEK] = "***" },
		"a short wrapped key":    func(h map[string]string) { h[metaDEK] = keys.EncodeWrapped([]byte("short")) },
		"a chunk size of words":  func(h map[string]string) { h[metaChunkSize] = "big" },
		"a chunk size past 255":  func(h map[string]string) { h[metaChunkSize] = "300" },
		"a chunk size too small": func(h map[string]string) { h[metaChunkSize] = "2" },
		"a manifest id of junk":  func(h map[string]string) { h[metaManifestID] = "not-an-id" },
	} {
		t.Run(name, func(t *testing.T) {
			headers := sample(t, true).Headers()
			edit(headers)
			if got, err := Parse(headers, stream.DefaultLog2ChunkSize); err == nil {
				t.Errorf("accepted: %+v", got)
			}
		})
	}
}
