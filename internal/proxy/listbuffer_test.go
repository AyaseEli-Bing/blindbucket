package proxy

import (
	"testing"
	"time"
)

// TestListingCache: the cache is an optimisation whose every miss re-reads the
// prefix, so what matters is that it never serves an expired or foreign
// listing, and never grows past its bound.
func TestListingCache(t *testing.T) {
	rows := func(key string) []listingRow { return []listingRow{{key: key}} }

	t.Run("a nil cache is a permanent miss", func(t *testing.T) {
		var c *listingCache
		c.put("b", "p/", "/", rows("x"))
		if _, ok := c.get("b", "p/", "/"); ok {
			t.Error("a nil cache returned a listing")
		}
	})

	t.Run("a listing is kept per bucket, prefix and delimiter", func(t *testing.T) {
		c := newListingCache(time.Minute, 8)
		c.put("b", "p/", "/", rows("x"))
		if got, ok := c.get("b", "p/", "/"); !ok || got[0].key != "x" {
			t.Fatalf("got %v, %t", got, ok)
		}
		for _, other := range [][3]string{{"other", "p/", "/"}, {"b", "q/", "/"}, {"b", "p/", ""}} {
			if _, ok := c.get(other[0], other[1], other[2]); ok {
				t.Errorf("%q served a listing cached for another request", other)
			}
		}
	})

	t.Run("an expired listing is not served", func(t *testing.T) {
		c := newListingCache(time.Nanosecond, 8)
		c.put("b", "p/", "/", rows("x"))
		time.Sleep(time.Millisecond)
		if _, ok := c.get("b", "p/", "/"); ok {
			t.Error("an expired listing was served")
		}
		if len(c.entries) != 0 {
			t.Error("the expired entry was not dropped")
		}
	})

	t.Run("the bound evicts the oldest", func(t *testing.T) {
		c := newListingCache(time.Minute, 2)
		c.put("b", "1/", "/", rows("1"))
		time.Sleep(time.Millisecond)
		c.put("b", "2/", "/", rows("2"))
		c.put("b", "3/", "/", rows("3"))
		if len(c.entries) != 2 {
			t.Fatalf("the cache holds %d entries, bound 2", len(c.entries))
		}
		if _, ok := c.get("b", "1/", "/"); ok {
			t.Error("the oldest entry survived an eviction")
		}
		if _, ok := c.get("b", "3/", "/"); !ok {
			t.Error("the newest entry was evicted")
		}
	})

	t.Run("expired entries go first", func(t *testing.T) {
		c := newListingCache(5*time.Millisecond, 2)
		c.put("b", "old/", "/", rows("old"))
		time.Sleep(10 * time.Millisecond)
		c.ttl = time.Minute // the next entry lives; the first is already past it
		c.entries["b\x00old/\x00/"].born = time.Now().Add(-2 * time.Minute)
		c.put("b", "kept/", "/", rows("kept"))
		c.put("b", "new/", "/", rows("new"))
		if _, ok := c.get("b", "kept/", "/"); !ok {
			t.Error("a live entry was evicted while an expired one could have gone")
		}
	})
}
