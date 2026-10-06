package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"

	"github.com/LennardGeissler/blindbucket/internal/crypto/envelope"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
)

// inspectMagicSize is the length of the marker that says which format the input
// claims to be. Every magic in docs/FORMAT.md is four bytes.
const inspectMagicSize = 4

// runInspect reports the format fields of a blindbucket file or a raw segment
// without decrypting it and without a keyring.
//
// It can do that because the format keeps its header in the clear
// (docs/FORMAT.md section 4.1) and makes the length reversible (section 7.2): the
// plaintext size falls out of the ciphertext size and the chunk size, which is the
// same arithmetic the proxy performs to answer a HEAD.
//
// The status of that number is already on the record for listings: the threat model
// (docs/THREAT_MODEL.md section 5.4) calls a size derived from what the provider
// reports a hint rather than a guarantee, the authenticated size being established
// only when the object is read. This command reports the same kind of number, and
// its usage says so.
func runInspect(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `Usage: blindbucket inspect [file]

Reports the format fields of a blindbucket file (BBF1, what encrypt writes) or of a
raw segment (BLBK, what the proxy stores per part): the chunk size, the part index,
the salt, the key id a file is wrapped under, and the plaintext size derived from the
length. Nothing is decrypted, and no keyring is read.

What is printed is what the headers claim. A header is authenticated together with
its chunks rather than on its own, so these fields say what a writer intended, not
what has been verified -- `+"`blindbucket decrypt`"+` is the command that verifies.

The sizes are arithmetic on the length. A length no encoder could produce is reported
as a failure; a length that fits is not proof of integrity, because bytes appended to
a ciphertext usually read as a sound segment of a different plaintext.

The ciphertext line counts the segment alone, so a file's envelope is excluded from
it. The file is read from stdin when the argument is absent or -.
`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 1 {
		fs.Usage()
		return fmt.Errorf("inspect takes one file, got %d arguments", fs.NArg())
	}

	path := "-"
	if fs.NArg() == 1 {
		path = fs.Arg(0)
	}
	if path == "-" && term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("no file given and stdin is a terminal; pass a file or pipe it in")
	}

	src, closeSrc, err := openInput(path)
	if err != nil {
		return err
	}
	defer closeSrc()

	prefix, err := readMagic(src)
	if err != nil {
		return inspectError(path, err)
	}
	// The magic decides the format, and both parsers want to read their header
	// from the first byte, so the four bytes are handed back rather than
	// duplicated into two partial readers.
	r := io.MultiReader(bytes.NewReader(prefix), src)

	var hdr envelope.Header
	isFile := string(prefix) == string(envelope.Magic[:])
	switch {
	case isFile:
		hdr, err = envelope.DecodeHeader(r)
		if err != nil {
			return inspectError(path, err)
		}
	case string(prefix) == string(stream.Magic[:]):
	case string(prefix) == string(manifest.Magic[:]), string(prefix) == string(manifest.MagicV1[:]):
		return inspectError(path, fmt.Errorf("this is a multipart manifest (%s), which records part sizes rather than a segment header; inspect reads files and segments",
			prefix))
	default:
		return inspectError(path, fmt.Errorf("bad magic %q: want %s for a file or %s for a segment",
			prefix, string(envelope.Magic[:]), string(stream.Magic[:])))
	}

	raw := make([]byte, stream.HeaderSize)
	read, err := io.ReadFull(r, raw)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		// `read` is already what the header got: on a segment the replayed magic is
		// part of it, and on a file the magic belongs to the envelope, which was
		// read whole before this point.
		return inspectError(path, truncatedHeaderError(isFile, read))
	}
	if err != nil {
		return inspectError(path, err)
	}
	params, salt, err := stream.DecodeHeader(raw)
	if err != nil {
		return inspectError(path, err)
	}
	// Section 9 of docs/FORMAT.md makes this more than a nicety: Decrypt asks the
	// stream decoder for a single-part segment with index 0, so a file whose header
	// disagrees with that is a file that will not open. Saying so here, before
	// anyone tries to open it, is what the command is for.
	if isFile && (params.Multipart || params.Index != 0) {
		return inspectError(path, fmt.Errorf("a file's segment must be single-part with index 0, got multipart=%t index=%d: decrypt will refuse it",
			params.Multipart, params.Index))
	}

	// A regular file's length is the number the format counts, so it is asked for
	// rather than summed: draining a 5 GiB object to discover that it holds 5 GiB
	// of bytes is not a diagnostic, it is a wait. A pipe has no length to ask, so
	// what was parsed is added to what is left: the envelope, the segment header,
	// and whatever the reader has not handed over yet.
	parsed := hdr.Size + stream.HeaderSize
	total, err := inputLength(ctx, path, r, parsed)
	if err != nil {
		return err
	}
	sealed := total - hdr.Size

	fields := [][2]string{{"format", formatName(isFile, prefix)}}
	if hdr.Size > 0 {
		fields = append(fields,
			[2]string{"key id", hdr.KeyID},
			[2]string{"envelope", fmt.Sprintf("%d bytes", hdr.Size)})
	}
	fields = append(fields,
		[2]string{"magic", string(stream.Magic[:])},
		[2]string{"version", fmt.Sprintf("%d", stream.Version)},
		[2]string{"chunk size", fmt.Sprintf("%d (log2 = %d)", params.ChunkSize(), params.Log2ChunkSize)},
		[2]string{"multipart", yesNo(params.Multipart)},
		[2]string{"part index", fmt.Sprintf("%d", params.Index)},
		[2]string{"salt", shortSalt(salt)},
		[2]string{"ciphertext", fmt.Sprintf("%d bytes", sealed)},
	)

	// The derived size is last because it is the only field not stored, and the
	// one that can fail: a length no encoder could produce means the input is
	// truncated, extended, or written with a chunk size it does not declare.
	plain, plainErr := stream.OpenedSize(sealed, params.Log2ChunkSize)
	if plainErr == nil {
		fields = append(fields, [2]string{"plaintext", fmt.Sprintf("%d bytes (derived)", plain)})
	}

	for _, f := range fields {
		_, _ = fmt.Fprintf(os.Stdout, "%-13s %s\n", f[0], f[1])
	}

	if plainErr != nil {
		// Everything readable has been printed, so the reader can identify the
		// segment, and the exit code still says the input is not a sound one: a
		// diagnostic that returned 0 on a file no decoder could read would be a
		// tool that vouches for the thing it exists to question.
		return inspectError(path, fmt.Errorf("no plaintext length corresponds to %d ciphertext bytes at chunk size 2^%d (%w)",
			sealed, params.Log2ChunkSize, plainErr))
	}
	return nil
}

// inspectError names the input in an error, since "-" is a path and stdin is what
// the user actually gave.
func inspectError(path string, err error) error {
	if path == "-" {
		return fmt.Errorf("stdin: %w", err)
	}
	return fmt.Errorf("%s: %w", path, err)
}

// readMagic reads the four bytes that identify a format.
func readMagic(src io.Reader) ([]byte, error) {
	prefix := make([]byte, inspectMagicSize)
	read, err := io.ReadFull(src, prefix)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, fmt.Errorf("input holds %d byte(s), too few to hold a format marker", read)
	}
	if err != nil {
		return nil, err
	}
	return prefix, nil
}

// truncatedHeaderError reports a segment header of which only `seen` bytes are
// present in the input.
func truncatedHeaderError(isFile bool, seen int) error {
	if isFile {
		return fmt.Errorf("the file is truncated: %d of the segment header's %d bytes follow its envelope",
			seen, stream.HeaderSize)
	}
	return fmt.Errorf("the input holds %d byte(s), fewer than the segment header's %d",
		seen, stream.HeaderSize)
}

// inputLength reports how many bytes the input holds in total, including the
// ones already parsed.
func inputLength(ctx context.Context, path string, r io.Reader, parsed int64) (int64, error) {
	if path != "-" {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return info.Size(), nil
		}
	}
	rest, err := countRemaining(ctx, r)
	if err != nil {
		return 0, err
	}
	return parsed + rest, nil
}

// countRemaining reads src to the end and reports how many bytes it held.
//
// It checks the context between reads because main turns Ctrl-C into a
// cancellation rather than a kill: a command that never looks at the context
// cannot be interrupted, and a pipe has no length to bound the wait by.
func countRemaining(ctx context.Context, src io.Reader) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		read, err := src.Read(buf)
		total += int64(read)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return total, nil
			}
			return 0, err
		}
	}
}

// formatName says which format the input turned out to be, by its marker.
func formatName(isFile bool, prefix []byte) string {
	if isFile {
		return fmt.Sprintf("file (%s)", prefix)
	}
	return fmt.Sprintf("segment (%s)", prefix)
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

// shortSalt prints the ends of a segment salt.
//
// The full value is 40 hex characters of random material that nobody compares by
// eye; the ends are enough to tell two segments apart, which is what this is
// printed for. It is not a secret: section 4.1 of docs/FORMAT.md keeps the header
// in the clear precisely so that a reader can find the subkey.
func shortSalt(salt [stream.SaltSize]byte) string {
	full := hex.EncodeToString(salt[:])
	return full[:4] + "…" + full[len(full)-4:]
}
