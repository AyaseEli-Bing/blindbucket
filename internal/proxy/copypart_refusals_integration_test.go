package proxy

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// partCopy issues an UploadPartCopy with any headers, for the cases mpuPartCopy
// cannot express: a source other than a key in the test bucket, or conditions.
func (h *harness) partCopy(
	t *testing.T, key, token, source string, headers map[string]string,
) *http.Response {
	t.Helper()
	target := fmt.Sprintf("%s?partNumber=1&uploadId=%s", h.url(key), urlQueryEscape(token))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, target, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.ContentLength = 0
	req.Header.Set("X-Amz-Copy-Source", source)
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("UploadPartCopy: %v", err)
	}
	return resp
}

// TestIntegrationUploadPartCopyRefusals is TestIntegrationCopyRefusals for the
// multipart copy path, which checks the same things through code of its own. A
// part copy that skipped the bucket check would let a credential read any
// bucket the gateway's upstream credentials can, by copying it into one it may.
func TestIntegrationUploadPartCopyRefusals(t *testing.T) {
	h := newHarness(t)
	src := testKey(t, "src.bin")
	h.store(t, src, randomBytes(t, 3000))
	info, err := h.upstream.HeadObject(context.Background(), testBucket, src)
	if err != nil {
		t.Fatalf("HEAD upstream: %v", err)
	}
	etag := strings.Trim(info.ETag, `"`)
	source := "/" + testBucket + "/" + src

	foreign := testKey(t, "foreign.bin")
	if _, err := h.upstream.PutObject(context.Background(), upstream.PutObjectInput{
		Bucket: testBucket, Key: foreign, Body: strings.NewReader("not ours"), ContentLength: 8,
	}); err != nil {
		t.Fatalf("writing the foreign object: %v", err)
	}
	t.Cleanup(func() { _ = h.upstream.DeleteObject(context.Background(), testBucket, foreign) })

	cases := []struct {
		name    string
		source  string
		headers map[string]string
		want    int
		code    string
	}{
		{"a bucket the credential does not have", "/other-bucket/some-key", nil,
			http.StatusForbidden, "AccessDenied"},
		{"the reserved prefix", "/" + testBucket + "/.blindbucket/anything", nil,
			http.StatusBadRequest, "InvalidRequest"},
		{"a malformed source", "not-a-path", nil, http.StatusBadRequest, ""},
		{"a missing source", "/" + testBucket + "/does-not-exist", nil, http.StatusNotFound, ""},
		{"an object this gateway did not write", "/" + testBucket + "/" + foreign, nil,
			0, "ObjectNotEncrypted"},
		{"a failed if-match", source,
			map[string]string{"X-Amz-Copy-Source-If-Match": strings.Repeat("0", 32)},
			http.StatusPreconditionFailed, "PreconditionFailed"},
		{"a matching if-none-match", source,
			map[string]string{"X-Amz-Copy-Source-If-None-Match": etag},
			http.StatusPreconditionFailed, "PreconditionFailed"},
		{"a range past the end", source,
			map[string]string{"X-Amz-Copy-Source-Range": "bytes=5000-5999"},
			http.StatusRequestedRangeNotSatisfiable, "InvalidRange"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dst := testKey(t, "dst.bin")
			token := h.mpuStart(t, dst, nil)
			resp := h.partCopy(t, dst, token, tc.source, tc.headers)
			defer func() { _ = resp.Body.Close() }()
			body := readBody(t, resp)
			if resp.StatusCode == http.StatusOK {
				t.Fatalf("the part copy was accepted: %s", body)
			}
			if tc.want != 0 && resp.StatusCode != tc.want {
				t.Errorf("returned %d, want %d: %s", resp.StatusCode, tc.want, body)
			}
			if tc.code != "" && !strings.Contains(body, "<Code>"+tc.code+"</Code>") {
				t.Errorf("the error is not %s: %s", tc.code, body)
			}
		})
	}
}

// TestIntegrationUploadPartCopyIntoAnEndedUpload covers the two ways the
// destination upload can be gone: an upload id the gateway never issued, and
// one it issued for an upload that has since been aborted.
func TestIntegrationUploadPartCopyIntoAnEndedUpload(t *testing.T) {
	h := newHarness(t)
	src := testKey(t, "src.bin")
	h.store(t, src, randomBytes(t, 3000))
	source := "/" + testBucket + "/" + src

	t.Run("an upload id the gateway never issued", func(t *testing.T) {
		dst := testKey(t, "dst.bin")
		resp := h.partCopy(t, dst, "not-a-sealed-token", source, nil)
		defer func() { _ = resp.Body.Close() }()
		if body := readBody(t, resp); resp.StatusCode != http.StatusNotFound ||
			!strings.Contains(body, "NoSuchUpload") {
			t.Errorf("returned %d: %s", resp.StatusCode, body)
		}
	})

	t.Run("an aborted upload", func(t *testing.T) {
		dst := testKey(t, "dst.bin")
		token := h.mpuStart(t, dst, nil)
		abort, err := http.NewRequestWithContext(t.Context(), http.MethodDelete,
			h.url(dst)+"?uploadId="+urlQueryEscape(token), nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		resp, err := h.client.Do(abort)
		if err != nil {
			t.Fatalf("abort: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("abort returned %d", resp.StatusCode)
		}

		// The token still opens -- it is sealed, not looked up -- so this is
		// the provider saying the upload is gone, passed on as what it means.
		resp = h.partCopy(t, dst, token, source, nil)
		defer func() { _ = resp.Body.Close() }()
		if body := readBody(t, resp); resp.StatusCode != http.StatusNotFound ||
			!strings.Contains(body, "NoSuchUpload") {
			t.Errorf("returned %d: %s", resp.StatusCode, body)
		}
	})
}
