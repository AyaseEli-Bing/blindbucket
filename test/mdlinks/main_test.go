package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// tree writes the named files into a temporary directory and returns that root
// with the file names, as Check wants them.
func tree(t *testing.T, files map[string]string) (string, []string) {
	t.Helper()
	root := t.TempDir()
	names := make([]string, 0, len(files))
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", name, err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return root, names
}

func keys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestSlug(t *testing.T) {
	for _, tc := range []struct {
		heading, want string
	}{
		// GitHub drops punctuation but keeps the spaces either side of it, so an
		// em dash or a code span leaves a double hyphen rather than a single one.
		{"Conditional writes, for rotation and migration", "conditional-writes-for-rotation-and-migration"},
		{"1. Cleanup against a concurrent upload — `MCLegacyCleanup`", "1-cleanup-against-a-concurrent-upload--mclegacycleanup"},
		{"Migrating names — `Migrate.tla`", "migrating-names--migratetla"},
		{"What `--json` promises", "what---json-promises"},
		{"snake_case stays", "snake_case-stays"},
		// A heading that links somewhere contributes the label, not the
		// destination.
		{"See the [format](docs/FORMAT.md) note", "see-the-format-note"},
		{"", ""},
	} {
		if got := slug(headingText(tc.heading)); got != tc.want {
			t.Errorf("slug(headingText(%q)) = %q, want %q", tc.heading, got, tc.want)
		}
	}
}

// TestAnchors covers the two ways a heading check fails quietly: the -1 suffix
// GitHub gives a repeated heading, and a heading inside a fenced block, which is
// an example rather than a heading of the document.
func TestAnchors(t *testing.T) {
	d := parse("# Title\n\n## Section\n\n```md\n## Not a heading\n```\n\n## Section\n")
	for _, want := range []string{"title", "section", "section-1"} {
		if !d.anchors[want] {
			t.Errorf("anchors = %v, want %q among them", keys(d.anchors), want)
		}
	}
	if d.anchors["not-a-heading"] {
		t.Errorf("a heading inside a fence counted as an anchor: %v", keys(d.anchors))
	}
}

// TestFenceWithInfoString guards the one bug in this tool that would hide
// everything: an opening fence carries a language, so counting any line that
// starts with three backticks as a close ends the block early and swallows every
// heading after it.
func TestFenceWithInfoString(t *testing.T) {
	d := parse("```sh\n$ blindbucket version\n```\n\n## Real heading\n")
	if !d.anchors["real-heading"] {
		t.Errorf("the heading after a closed fence vanished: %v", keys(d.anchors))
	}
}

// TestInlineLinks checks which destinations come out of a line and which do
// not. A destination GitHub does not render as a link must not be reported, and
// brackets that are only prose must not become one either.
func TestInlineLinks(t *testing.T) {
	for _, tc := range []struct {
		name, line string
		want       []string
	}{
		{"plain", `see [the format](docs/FORMAT.md) for it`, []string{"docs/FORMAT.md"}},
		{"title", `see [it](docs/FORMAT.md "the format")`, []string{"docs/FORMAT.md"}},
		{"angle brackets", `see [it](<docs/a b.md>)`, []string{"docs/a b.md"}},
		{"parenthesis inside", `see [nested](<docs/a(b).md>)`, []string{"docs/a(b).md"}},
		{"image", `![screenshot](demo/demo.gif)`, []string{"demo/demo.gif"}},
		{"bare anchor", `[up](#section)`, nil},
		{"external", `[ci](https://example.com/x.md)`, nil},
		{"host relative", `[x](//example.com/a)`, nil},
		{"mail address", `[mail](mailto:a@b.c)`, nil},
		{"brackets in prose", `the flag [A] or [B] both work`, nil},
		{"reference use", `see [fmt][f] and [f][]`, nil},
		{"code span", "write `[x](missing.md)` verbatim", nil},
	} {
		// inlineLinks reports every destination it finds; the checker then
		// resolves only those that name something in the repository. This is what
		// a reader of the test wants to see, so the filter is applied here.
		var got []string
		for _, dest := range inlineLinks(blankCodeSpans(tc.line)) {
			if skip(dest) {
				continue
			}
			got = append(got, dest)
		}
		if len(got) != len(tc.want) {
			t.Errorf("%s: destinations in %q = %q, want %q", tc.name, tc.line, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: destinations in %q = %q, want %q", tc.name, tc.line, got, tc.want)
				break
			}
		}
	}
}

// TestSkipDestinations names what the checker is told to leave alone.
func TestSkipDestinations(t *testing.T) {
	for _, dest := range []string{"", "#anchor", "https://x/y", "http://x", "mailto:a@b", "//x/y", "gs://bucket/o"} {
		if !skip(dest) {
			t.Errorf("skip(%q) = false; only files in this repository should be resolved", dest)
		}
	}
	for _, dest := range []string{"docs/x.md", "../x.md", "/README.md", "x#y"} {
		if skip(dest) {
			t.Errorf("skip(%q) = true; this names something in the repository", dest)
		}
	}
}

// TestCleanTree is the shape the repository is in today: every relative
// destination resolves, and the checker resolves a real number of them rather
// than reporting success having found nothing.
func TestCleanTree(t *testing.T) {
	problems, checked := mustCheck(t, map[string]string{
		"README.md":      "# Title\n\n[format](docs/FORMAT.md)\n[up](#title)\n[here](docs/FORMAT.md#section)\n![img](demo/a.png)\n\n```md\n[fake](missing.md)\n```\n",
		"docs/FORMAT.md": "# Format\n\n## Section\n\n[back](../README.md#title)\n[space](a%20b.md)\n[def][l]\n\n[l]: ../README.md\n",
		"docs/a b.md":    "# Space\n",
		"demo/a.png":     "not a png, but it exists\n",
		"spec/tla/x.md":  "## Migrating names — `Migrate.tla`\n\n[down](#migrating-names--migratetla)\n",
		"CHANGELOG.md":   "# Changelog\n\n[1.0]: https://example.com/v1.0.0\n",
	})
	if len(problems) != 0 {
		t.Errorf("a clean tree reported problems:\n%s", strings.Join(problems, "\n"))
	}
	if checked < 6 {
		t.Errorf("only %d destinations resolved; the tree holds more, so the parser missed some", checked)
	}
}

// TestBrokenLinks is why the job exists. Each case is a link a reader would
// click and land nowhere, and each has to be reported with the file and line a
// contributor can act on.
func TestBrokenLinks(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"missing file", "# T\n\n[a](missing.md)\n", "missing.md is not in the repository"},
		{"missing directory", "# T\n\n[a](nogdir/)\n", "nogdir/ is not in the repository"},
		{"wrong case", "# T\n\n[a](../readme.md)\n", "../readme.md is not in the repository"},
		{"up one level is fine", "# T\n\n[a](../outside.md)\n", ""},
		{"leaves the repository", "# T\n\n[a](../../outside.md)\n", "../../outside.md leaves the repository"},
		{"heading in another file", "# T\n\n[k](../README.md#gone)\n", "../README.md has no heading #gone"},
		{"heading in this file", "# T\n\n[k](#gone)\n", "#gone names no heading in this file"},
		{"third duplicate heading", "# T\n\n## Same\n\n## Same\n\n[k](#same-2)\n", "#same-2 names no heading"},
		{"reference definition", "# T\n\n[k][l]\n\n[l]: nowhere.md\n", "nowhere.md is not in the repository"},
		{"missing image", "# T\n\n![i](demo/gone.png)\n", "demo/gone.png is not in the repository"},
		{"link in a heading", "# T\n\n## See [gone](nope.md)\n", "nope.md is not in the repository"},
	} {
		root, names := tree(t, map[string]string{
			"README.md":      "# Readme\n\n## Keep\n",
			"docs/tool.md":   tc.body,
			"outside.md":     "# Outside\n",
			"nodir/keep.txt": "so a directory that exists is told from one that does not\n",
		})
		problems, _ := Check(root, names)
		var lines []string
		for _, p := range problems {
			lines = append(lines, p.String())
		}
		if tc.want == "" {
			if len(problems) != 0 {
				t.Errorf("%s: a link that resolves was reported:\n%s", tc.name, strings.Join(lines, "\n"))
			}
			continue
		}
		if len(problems) != 1 {
			t.Errorf("%s: got %d problems, want exactly 1:\n%s", tc.name, len(problems), strings.Join(lines, "\n"))
			continue
		}
		if !strings.Contains(lines[0], tc.want) {
			t.Errorf("%s: problem %q does not say %q", tc.name, lines[0], tc.want)
		}
		// The reader has to find the line, so the report names the file the link
		// is in rather than the file it points at.
		if !strings.HasPrefix(lines[0], "docs/tool.md:") {
			t.Errorf("%s: problem %q does not name the file holding the link", tc.name, lines[0])
		}
	}
}

// TestReportsTheLine pins the line number of the simplest case, so a change to
// how lines are counted cannot quietly shift every report by one.
func TestReportsTheLine(t *testing.T) {
	problems, _ := mustCheck(t, map[string]string{
		"docs/tool.md": "# T\n\nsecond\n\n[a](missing.md)\n",
	})
	if len(problems) != 1 || problems[0] != "docs/tool.md:5: missing.md is not in the repository" {
		t.Errorf("got %q, want the report to point at line 5", problems)
	}
}

// mustCheck runs Check over a temporary tree and renders the problems.
func mustCheck(t *testing.T, files map[string]string) ([]string, int) {
	t.Helper()
	root, names := tree(t, files)
	problems, checked := Check(root, names)
	out := make([]string, 0, len(problems))
	for _, p := range problems {
		out = append(out, p.String())
	}
	return out, checked
}
