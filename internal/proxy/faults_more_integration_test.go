package proxy

import (
	"net/http"
	"strings"
	"testing"
)

// gatewayDo sends a request with a query to the gateway and returns the status
// and body.
func (h *harness) gatewayDo(t *testing.T, method, key, query string) (int, string) {
	t.Helper()
	target := h.url(key)
	if key == "" {
		target = h.proxy.URL + "/" + testBucket
	}
	req, err := http.NewRequestWithContext(t.Context(), method, target+"?"+query, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, query, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, readBody(t, resp)
}

// TestListMultipartUploadsIsRefused pins the one call deliberately left out:
// the upload ids this gateway hands out are sealed tokens, and the provider's
// listing holds only its own ids, which no client could use.
func TestIntegrationListMultipartUploadsIsRefused(t *testing.T) {
	h := newHarness(t)
	status, body := h.gatewayDo(t, http.MethodGet, "", "uploads")
	if status != http.StatusNotImplemented || !strings.Contains(body, "NotImplemented") {
		t.Errorf("returned %d: %s", status, body)
	}
}

// TestIntegrationEndedUploads: every call on an upload that no longer exists
// says NoSuchUpload, which is what a client retrying the whole upload acts on.
func TestIntegrationEndedUploads(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "ended.bin")
	token := h.mpuStart(t, key, nil)
	etag, resp := h.mpuPart(t, key, token, 1, randomBytes(t, 1000))
	_ = resp.Body.Close()

	// While it is open, ListParts reports the part in plaintext size.
	status, body := h.gatewayDo(t, http.MethodGet, key, "uploadId="+urlQueryEscape(token))
	if status != http.StatusOK || !strings.Contains(body, "<Size>1000</Size>") {
		t.Errorf("ListParts on an open upload returned %d: %s", status, body)
	}

	if status, body := h.gatewayDo(t, http.MethodDelete, key, "uploadId="+urlQueryEscape(token)); status != http.StatusNoContent {
		t.Fatalf("abort returned %d: %s", status, body)
	}

	for name, call := range map[string]func() (int, string){
		"ListParts": func() (int, string) {
			return h.gatewayDo(t, http.MethodGet, key, "uploadId="+urlQueryEscape(token))
		},
		"completion": func() (int, string) {
			resp := h.mpuComplete(t, key, token, []completeReqPart{{PartNumber: 1, ETag: etag}})
			defer func() { _ = resp.Body.Close() }()
			return resp.StatusCode, readBody(t, resp)
		},
	} {
		t.Run(name, func(t *testing.T) {
			status, body := call()
			if status != http.StatusNotFound || !strings.Contains(body, "NoSuchUpload") {
				t.Errorf("returned %d: %s", status, body)
			}
		})
	}
}

// TestIntegrationTaggingOnAProviderWithout: the AWS CLI asks for an object's
// tags before every multipart server-side copy. Garage does not implement
// tagging, and a 502 there failed the copy; its true answer is no tags.
func TestIntegrationTaggingOnAProviderWithout(t *testing.T) {
	f := newFaultyProvider(t)
	h := newHarness(t, f.option(t))
	key := testKey(t, "tags.bin")
	h.store(t, key, []byte("tagged, or not"))

	// Against MinIO the request is forwarded and answered by it.
	if status, body := h.gatewayDo(t, http.MethodGet, key, "tagging"); status != http.StatusOK ||
		!strings.Contains(body, "Tagging") {
		t.Fatalf("GET ?tagging returned %d: %s", status, body)
	}

	rule := f.fail(&fault{match: objectRequest(http.MethodGet, key, "tagging"), times: 1,
		status: http.StatusNotImplemented, code: "NotImplemented"})
	status, body := h.gatewayDo(t, http.MethodGet, key, "tagging")
	if f.hits(rule) == 0 {
		t.Fatal("the fault was never reached")
	}
	if status != http.StatusOK || !strings.Contains(body, "<TagSet></TagSet>") {
		t.Errorf("a provider without tagging gave %d: %s", status, body)
	}

	// Any other failure is not dressed up as an empty tag set.
	f.fail(&fault{match: objectRequest(http.MethodGet, key, "tagging"), status: http.StatusInternalServerError})
	if status, _ := h.gatewayDo(t, http.MethodGet, key, "tagging"); status < 500 {
		t.Errorf("a failed tagging request answered %d", status)
	}
}

// TestIntegrationVersionIDIsPassedOn: on a versioned bucket the provider names
// the version it stored, and a client that asked for it must get it back.
// MinIO's test bucket is unversioned, so the header is added on its way back.
func TestIntegrationVersionIDIsPassedOn(t *testing.T) {
	f := newFaultyProvider(t)
	h := newHarness(t, f.option(t))

	put := testKey(t, "versioned.bin")
	f.fail(&fault{match: plainPut(put), setHeader: map[string]string{"x-amz-version-id": "v-put"}})
	resp := h.put(t, put, []byte("versioned"), nil)
	_ = resp.Body.Close()
	if got := resp.Header.Get("x-amz-version-id"); got != "v-put" {
		t.Errorf("PutObject returned version %q, want v-put", got)
	}

	mpu := testKey(t, "versioned-mpu.bin")
	f.fail(&fault{match: objectRequest(http.MethodPost, mpu, "uploadId"),
		setHeader: map[string]string{"x-amz-version-id": "v-mpu"}})
	token := h.mpuStart(t, mpu, nil)
	etag, resp := h.mpuPart(t, mpu, token, 1, randomBytes(t, 1000))
	_ = resp.Body.Close()
	resp = h.mpuComplete(t, mpu, token, []completeReqPart{{PartNumber: 1, ETag: etag}})
	_ = resp.Body.Close()
	if got := resp.Header.Get("x-amz-version-id"); got != "v-mpu" {
		t.Errorf("CompleteMultipartUpload returned version %q, want v-mpu", got)
	}
}

// TestFaultReadsFailBeforeAnyBody: a failure before the first byte is an error
// status, never an empty 200. A read is one GET -- the metadata comes with the
// body, with no HEAD before it -- plus, for a range, one for the header.
func TestFaultReadsFailBeforeAnyBody(t *testing.T) {
	for name, template := range map[string]fault{
		"the provider refuses": {times: 1, status: 500},
		// Every time: Go's transport retries an idempotent GET once on its own
		// when a connection dies before answering, and the retry then succeeds.
		"the connection drops": {drop: true},
	} {
		for _, rng := range []string{"", "bytes=200000-249999"} {
			t.Run(name+" "+rng, func(t *testing.T) {
				f := newFaultyProvider(t)
				h := newHarness(t, f.option(t))
				key := testKey(t, "read.bin")
				h.store(t, key, randomBytes(t, 300_000))

				rule := template
				rule.match = objectRequest(http.MethodGet, key)
				f.fail(&rule)
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.url(key), nil)
				if err != nil {
					t.Fatalf("request: %v", err)
				}
				if rng != "" {
					req.Header.Set("Range", rng)
				}
				resp, err := h.client.Do(req)
				if err != nil {
					t.Fatalf("GET: %v", err)
				}
				_ = resp.Body.Close()
				if f.hits(&rule) == 0 {
					t.Fatal("the fault was never reached")
				}
				if resp.StatusCode < 500 {
					t.Errorf("a read whose provider call failed answered %d", resp.StatusCode)
				}
			})
		}
	}
}

// TestFaultDeletingAMultipartObjectKeepsGoing: the object is gone once the
// provider deletes it; its manifest is clean-up, and a failure there leaves an
// orphan for gc rather than failing a delete that happened.
func TestFaultDeletingAMultipartObjectKeepsGoing(t *testing.T) {
	f := newFaultyProvider(t)
	h := newHarness(t, f.option(t))
	key := testKey(t, "delete-mpu.bin")
	h.mpuStore(t, key, [][]byte{randomBytes(t, testPart), randomBytes(t, 1000)})
	manifestKey, _ := h.manifestKeyOf(t, key)
	h.cleanupStored(t, manifestKey)

	rule := f.fail(&fault{match: manifestRequest(http.MethodDelete), status: 500})
	resp := h.do(t, http.MethodDelete, key)
	_ = resp.Body.Close()
	if f.hits(rule) == 0 {
		t.Fatal("the fault was never reached")
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("the delete returned %d although the object was removed", resp.StatusCode)
	}
	h.absentUpstream(t, key)
}
