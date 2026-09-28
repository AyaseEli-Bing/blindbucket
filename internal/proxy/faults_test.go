package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/s3api"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// faultyProvider sits between the gateway and the real provider and fails the
// requests a test picks: with an S3 error, by dropping the connection before
// answering, or by cutting a response off partway through its body.
//
// Every other request is forwarded untouched, Host header included, so the
// gateway's signatures still verify at the provider. The harness keeps its own
// direct client, which is how a test sees what the provider really holds after
// the gateway was told something failed.
type faultyProvider struct {
	srv *httptest.Server

	mu    sync.Mutex
	rules []*fault
}

// fault is one injected failure.
type fault struct {
	match func(*http.Request) bool
	// times is how many matching requests fail; later ones pass. Zero means all.
	times int

	status   int    // answer with this status and an S3 error document
	code     string // the error code in that document; InjectedFault if empty
	drop     bool   // close the connection without answering
	cutAfter int64  // forward, but end the response body after this many bytes
	// setHeader forwards the request and adds these to the provider's answer,
	// for what a real provider would send and MinIO does not.
	setHeader map[string]string

	hits int
}

type ruleKey struct{}

func newFaultyProvider(t *testing.T) *faultyProvider {
	t.Helper()
	target, err := url.Parse(upstreamConfig(t).Endpoint)
	if err != nil {
		t.Fatalf("parsing the provider endpoint: %v", err)
	}
	f := &faultyProvider{}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			// The gateway signed for this host; the provider checks it as sent.
			pr.Out.Host = pr.In.Host
		},
		ModifyResponse: func(resp *http.Response) error {
			rule, ok := resp.Request.Context().Value(ruleKey{}).(*fault)
			if !ok {
				return nil
			}
			if rule.cutAfter > 0 {
				resp.Body = &cutBody{r: resp.Body, left: rule.cutAfter}
			}
			for name, value := range rule.setHeader {
				resp.Header.Set(name, value)
			}
			return nil
		},
		// A cut body surfaces here; aborting the handler is what makes the
		// gateway see a broken connection rather than a short, clean response.
		ErrorHandler: func(http.ResponseWriter, *http.Request, error) { panic(http.ErrAbortHandler) },
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rule := f.take(r)
		switch {
		case rule == nil:
			rp.ServeHTTP(w, r)
		case rule.drop:
			_, _ = io.Copy(io.Discard, r.Body)
			panic(http.ErrAbortHandler)
		case rule.status != 0:
			_, _ = io.Copy(io.Discard, r.Body)
			code := rule.code
			if code == "" {
				code = "InjectedFault"
			}
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(rule.status)
			_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>`+
				`<Error><Code>%s</Code><Message>injected by the test</Message></Error>`, code)
		default:
			rp.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ruleKey{}, rule)))
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// fail adds a fault and returns it, so a test can check that it was reached.
func (f *faultyProvider) fail(rule *fault) *fault {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = append(f.rules, rule)
	return rule
}

func (f *faultyProvider) take(r *http.Request) *fault {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, rule := range f.rules {
		if (rule.times == 0 || rule.hits < rule.times) && rule.match(r) {
			rule.hits++
			return rule
		}
	}
	return nil
}

func (f *faultyProvider) hits(rule *fault) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return rule.hits
}

// option points a harness's gateway at the faulty provider, with retries off so
// that one injected failure is one failure the gateway sees.
func (f *faultyProvider) option(t *testing.T) func(*Config) {
	t.Helper()
	cfg := upstreamConfig(t)
	cfg.Endpoint = f.srv.URL
	cfg.MaxRetries = 1
	client, err := upstream.New(cfg)
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}
	return func(c *Config) { c.Upstream = client }
}

// cutBody ends a response body early with an error.
type cutBody struct {
	r    io.ReadCloser
	left int64
}

func (c *cutBody) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, errors.New("connection cut by the test")
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

func (c *cutBody) Close() error { return c.r.Close() }

// Request matchers. Keys are matched by substring of the path, which is enough
// to tell an object from its manifest under the reserved prefix.

func isManifest(r *http.Request) bool {
	return strings.Contains(r.URL.Path, "/"+s3api.ReservedPrefix)
}

func objectRequest(method, keyPart string, query ...string) func(*http.Request) bool {
	return func(r *http.Request) bool {
		if r.Method != method || isManifest(r) || !strings.Contains(r.URL.Path, keyPart) {
			return false
		}
		for _, q := range query {
			if !r.URL.Query().Has(q) {
				return false
			}
		}
		return true
	}
}

func manifestRequest(method string) func(*http.Request) bool {
	return func(r *http.Request) bool { return r.Method == method && isManifest(r) }
}
