// Command mdlinks checks the relative links in the repository's Markdown files.
//
// It answers one question: does a link that names a file or a heading inside
// this repository still point at it? A renamed ADR or a reworded heading breaks
// those silently, and the reader is the first to notice.
//
// External URLs are deliberately not checked. They fail for reasons that have
// nothing to do with the change under test, and a check that fails at random
// gets ignored. Links inside fenced code blocks and inside inline code spans
// are skipped too, because GitHub does not render them as links. Reference-style
// links are followed through their definition; a bracketed word with no
// definition is not a link and is left alone.
//
// Run from the repository root: go run ./test/mdlinks
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// Problem is one link that does not resolve, phrased for a reader who has the
// file open at the reported line.
type Problem struct {
	File   string
	Line   int
	Reason string
}

func (p Problem) String() string {
	return fmt.Sprintf("%s:%d: %s", p.File, p.Line, p.Reason)
}

// atxRE matches an ATX heading. Up to three leading spaces are still a heading;
// four begin an indented code block instead.
var atxRE = regexp.MustCompile(`^ {0,3}#{1,6}[ \t]+([^ \t].*)$`)

// defRE matches a link reference definition, `[label]: destination`.
var defRE = regexp.MustCompile(`^ {0,3}\[([^\]]+)\]:[ \t]*(\S+)`)

// schemeRE matches a destination that names a protocol rather than a file.
var schemeRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.\-]*:`)

// document is one parsed Markdown file: what it links to, and which anchors its
// headings provide.
type document struct {
	links   []rawLink
	anchors map[string]bool
}

type rawLink struct {
	line int
	dest string
}

// parse reads a document once and keeps what a link check needs from it.
func parse(content string) *document {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	d := &document{anchors: map[string]bool{}}
	seen := map[string]int{}
	inside := ""

	for i, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimLeft(line, " \t")
		marker := ""
		switch {
		case strings.HasPrefix(trimmed, "```"):
			marker = "```"
		case strings.HasPrefix(trimmed, "~~~"):
			marker = "~~~"
		}
		if marker != "" {
			// A fence that opens may carry an info string; one that closes may
			// not. Reading it the other way round ends a block early and swallows
			// everything after it, which is how a heading can go missing.
			switch {
			case inside == "":
				inside = marker
			case strings.HasPrefix(trimmed, inside) &&
				strings.TrimSpace(strings.TrimPrefix(trimmed, inside)) == "":
				inside = ""
			}
			continue
		}
		if inside != "" {
			continue
		}

		// A definition is the one place a reference-style link is checked: every
		// use of the label resolves to this destination, and a bracketed word with
		// no definition is prose rather than a link, so the uses are not followed.
		if m := defRE.FindStringSubmatch(line); m != nil {
			d.links = append(d.links, rawLink{line: i + 1, dest: cleanDest(m[2])})
			continue
		}

		// Headings are recorded before their links are read, so a document can
		// resolve anchors into itself, and so a heading that links somewhere is
		// still checked. The anchor comes from the line as written: code spans
		// inside a heading keep their text in the anchor GitHub builds.
		if m := atxRE.FindStringSubmatch(line); m != nil {
			base := slug(headingText(m[1]))
			if base != "" {
				n := seen[base]
				seen[base]++
				if n == 0 {
					d.anchors[base] = true
				} else {
					d.anchors[fmt.Sprintf("%s-%d", base, n)] = true
				}
			}
		}

		text := blankCodeSpans(line)
		for _, dest := range inlineLinks(text) {
			d.links = append(d.links, rawLink{line: i + 1, dest: dest})
		}
	}
	return d
}

// inlineLinks returns the destination of every inline link and image in one
// line of text, with the angle brackets and the title dropped. A bracketed run
// not followed by a parenthesis is reference-style or plain text, and the caller
// handles those through the definitions instead.
func inlineLinks(text string) []string {
	var out []string
	for i := 0; i < len(text); {
		if text[i] != '[' {
			i++
			continue
		}
		at := strings.IndexByte(text[i+1:], ']')
		if at < 0 {
			break
		}
		closed := i + 1 + at
		if closed+1 >= len(text) || text[closed+1] != '(' {
			i = closed + 1
			continue
		}
		// Read to the matching close parenthesis: a destination may hold one
		// when it is angle-bracketed, and a title may hold parentheses.
		k, depth := closed+2, 1
		for k < len(text) && depth > 0 {
			switch text[k] {
			case '(':
				depth++
			case ')':
				depth--
			}
			k++
		}
		if depth != 0 {
			break
		}
		out = append(out, cleanDest(text[closed+2:k-1]))
		i = k
	}
	return out
}

// slug turns heading text into the anchor GitHub gives it: lower case, spaces to
// hyphens, punctuation dropped. These are github-slugger's rules, which is what
// GitHub renders with, so an em dash or a pair of backticks leaves nothing
// behind but the surrounding spaces still become hyphens:
//
//	"### 1. Cleanup against a concurrent upload — `MCLegacyCleanup`"
//	  -> 1-cleanup-against-a-concurrent-upload--mclegacycleanup
func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == ' ' || r == '\t':
			b.WriteRune('-')
		case r == '-' || r == '_':
			b.WriteRune(r)
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
		}
	}
	return b.String()
}

// headingLabelRE matches an inline link inside a heading; GitHub uses the label
// and drops the destination when it builds the anchor.
var headingLabelRE = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`)

// headingText keeps the visible text of a heading that links or emphasises
// something: the label of each inline link, the words each delimiter surrounded.
func headingText(s string) string {
	s = headingLabelRE.ReplaceAllString(s, "$1")
	s = strings.ReplaceAll(s, "`", "")
	s = strings.ReplaceAll(s, "*", "")
	return s
}

// blankCodeSpans replaces what sits between backticks with spaces, so a path
// written in code style is not read as a link. The delimiters and the column of
// everything after them are kept, so reported positions stay honest.
func blankCodeSpans(line string) string {
	var out strings.Builder
	i := 0
	for i < len(line) {
		if line[i] != '`' {
			out.WriteByte(line[i])
			i++
			continue
		}
		j := i
		for j < len(line) && line[j] == '`' {
			j++
		}
		tick := line[i:j]
		end := strings.Index(line[j:], tick)
		if end < 0 {
			out.WriteString(tick)
			i = j
			continue
		}
		out.WriteString(tick)
		out.WriteString(strings.Repeat(" ", end))
		out.WriteString(tick)
		i = j + end + len(tick)
	}
	return out.String()
}

// cleanDest drops the angle brackets and the title a destination may carry. The
// brackets are the form that holds a space, so they are read first: trimming at
// the first space before them would cut `<docs/a b.md>` down to `<docs/a`.
func cleanDest(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "<") {
		if i := strings.IndexByte(s, '>'); i > 0 {
			return s[1:i]
		}
		return strings.TrimPrefix(s, "<")
	}
	if i := strings.IndexByte(s, ' '); i >= 0 {
		s = s[:i]
	}
	return s
}

// skip reports whether a destination is not this repository's business: empty, a
// bare anchor, a protocol, or a host-relative path.
func skip(dest string) bool {
	return dest == "" || strings.HasPrefix(dest, "#") ||
		schemeRE.MatchString(dest) || strings.HasPrefix(dest, "//")
}

// checker walks the repository, parsing each document once and caching it.
type checker struct {
	root    string
	cache   map[string]*document
	checked int // relative destinations resolved, so a quiet run can be told from an empty one
}

// doc returns the parsed form of a repository-relative path.
func (c *checker) doc(rel string) (*document, error) {
	if d, ok := c.cache[rel]; ok {
		return d, nil
	}
	body, err := os.ReadFile(filepath.Join(c.root, filepath.FromSlash(rel)))
	if err != nil {
		return nil, err
	}
	d := parse(string(body))
	c.cache[rel] = d
	return d, nil
}

// check resolves every relative destination of one parsed document.
func (c *checker) check(rel string, d *document) []Problem {
	var problems []Problem
	for _, l := range d.links {
		dest := l.dest
		if dest == "" {
			continue
		}
		filePart, anchor := dest, ""
		if i := strings.IndexByte(dest, '#'); i >= 0 {
			filePart, anchor = dest[:i], dest[i+1:]
		}
		if filePart == "" {
			// A bare anchor: it points into this document.
			c.checked++
			if anchor != "" && !d.anchors[anchor] {
				problems = append(problems, Problem{rel, l.line,
					fmt.Sprintf("#%s names no heading in this file", anchor)})
			}
			continue
		}
		if skip(filePart) {
			continue
		}
		c.checked++
		target, why := c.path(rel, filePart)
		if why != "" {
			problems = append(problems, Problem{rel, l.line, fmt.Sprintf("%s %s", filePart, why)})
			continue
		}
		if anchor == "" || !strings.HasSuffix(target, ".md") {
			continue
		}
		td, err := c.doc(target)
		if err != nil {
			problems = append(problems, Problem{rel, l.line, fmt.Sprintf("%s cannot be read: %v", filePart, err)})
			continue
		}
		if !td.anchors[anchor] {
			problems = append(problems, Problem{rel, l.line,
				fmt.Sprintf("%s has no heading #%s", filePart, anchor)})
		}
	}
	return problems
}

// path resolves one file part of a destination against the repository root, and
// refuses a spelling that only a case-insensitive filesystem would accept.
func (c *checker) path(from, filePart string) (string, string) {
	if decoded, err := decodePath(filePart); err == nil {
		filePart = decoded
	}
	var rel string
	if strings.HasPrefix(filePart, "/") {
		rel = path.Clean(strings.TrimPrefix(filePart, "/"))
	} else {
		rel = path.Clean(path.Join(path.Dir(from), filePart))
	}
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", "leaves the repository"
	}
	if !c.exists(rel) {
		return "", "is not in the repository"
	}
	return rel, ""
}

// exists reports whether root/rel exists, comparing every segment's spelling.
// os.Stat alone would accept a wrong case on macOS, where CI would then fail.
func (c *checker) exists(rel string) bool {
	cur := c.root
	for _, part := range strings.Split(rel, "/") {
		if part == "" || part == "." {
			continue
		}
		entries, err := os.ReadDir(cur)
		if err != nil {
			return false
		}
		next := ""
		for _, e := range entries {
			if e.Name() == part {
				next = filepath.Join(cur, part)
				break
			}
		}
		if next == "" {
			return false
		}
		cur = next
	}
	return true
}

// decodePath percent-decodes a destination, as GitHub does before resolving it.
func decodePath(s string) (string, error) {
	if !strings.Contains(s, "%") {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '%' || i+2 >= len(s) {
			b.WriteByte(s[i])
			i++
			continue
		}
		v, err := hexByte(s[i+1 : i+3])
		if err != nil {
			return s, err
		}
		b.WriteByte(v)
		i += 3
	}
	return b.String(), nil
}

func hexByte(s string) (byte, error) {
	var v int
	for _, ch := range s {
		v <<= 4
		switch {
		case ch >= '0' && ch <= '9':
			v |= int(ch - '0')
		case ch >= 'a' && ch <= 'f':
			v |= int(ch-'a') + 10
		case ch >= 'A' && ch <= 'F':
			v |= int(ch-'A') + 10
		default:
			return 0, fmt.Errorf("%q is not hexadecimal", string(ch))
		}
	}
	return byte(v), nil
}

// Check resolves every relative link in the named files, all read relative to
// root. The returned problems are ordered by file, then line; the count is how
// many destinations were resolved at all, so a clean run can be told apart from
// one that found nothing to check.
func Check(root string, files []string) ([]Problem, int) {
	c := &checker{root: root, cache: map[string]*document{}}
	var problems []Problem
	for _, rel := range files {
		d, err := c.doc(rel)
		if err != nil {
			problems = append(problems, Problem{rel, 0, fmt.Sprintf("cannot be read: %v", err)})
			continue
		}
		problems = append(problems, c.check(rel, d)...)
	}
	sort.SliceStable(problems, func(i, j int) bool {
		if problems[i].File != problems[j].File {
			return problems[i].File < problems[j].File
		}
		return problems[i].Line < problems[j].Line
	})
	return problems, c.checked
}

// trackedMarkdown lists the Markdown files git tracks, so a file that is ignored
// or deleted but still on disk is not checked.
func trackedMarkdown(root string) ([]string, error) {
	cmd := exec.Command("git", "ls-files", "-z", "--", "*.md")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var files []string
	for _, f := range strings.Split(string(out), "\x00") {
		if f != "" {
			files = append(files, filepath.ToSlash(f))
		}
	}
	sort.Strings(files)
	return files, nil
}

func main() {
	files, err := trackedMarkdown(".")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mdlinks: listing tracked Markdown files: %v\n", err)
		os.Exit(2)
	}
	problems, checked := Check(".", files)
	if len(files) > 0 && checked == 0 {
		// Passing quietly while resolving nothing would be worse than not
		// checking at all, so treat that as a fault in this tool.
		fmt.Fprintf(os.Stderr, "mdlinks: %d Markdown file(s) but no relative link resolved\n", len(files))
		os.Exit(2)
	}
	for _, p := range problems {
		fmt.Println(p)
	}
	if len(problems) > 0 {
		fmt.Fprintf(os.Stderr, "mdlinks: %d of %d relative link(s) do not resolve\n",
			len(problems), checked)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "mdlinks: %d relative link(s) across %d Markdown file(s), all resolve\n",
		checked, len(files))
}
