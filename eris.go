package main

import (
	"archive/tar"
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"golang.org/x/crypto/blake2b"
)

func CollectBlocks(store BlockStore, block_size int, level uint8, reference, key []byte, seen map[string]struct{}, fn func(ref, block []byte) error) error {
	if _, ok := seen[string(reference)]; ok {
		return nil
	}
	seen[string(reference)] = struct{}{}

	block, err := store.Get(reference)
	if err != nil {
		return err
	}
	if err := fn(reference, block); err != nil {
		return err
	}
	if level == 0 {
		return nil
	}

	node, err := DereferenceNode(store, ReferencePair{reference, key}, level, block_size)
	if err != nil {
		return err
	}
	for pair := range slices.Chunk(node, 64) {
		if bytes.Equal(pair, zeroPair[:]) {
			break
		}
		if err := CollectBlocks(store, block_size, level-1, pair[:32], pair[32:], seen, fn); err != nil {
			return err
		}
	}
	return nil
}

func ErisPack(store BlockStore, urn string, out io.Writer) error {
	cap, err := DecodeURN(urn)
	if err != nil {
		return err
	}
	if cap.level > 0 {
		if err := VerifyKey(store, cap.block_size, cap.level, cap.root_reference, cap.root_key); err != nil {
			return err
		}
	}

	tw := tar.NewWriter(out)
	seen := make(map[string]struct{})
	err = CollectBlocks(store, cap.block_size, cap.level, cap.root_reference, cap.root_key, seen, func(ref, block []byte) error {
		hdr := &tar.Header{
			Name: hex.EncodeToString(ref),
			Mode: 0o644,
			Size: int64(len(block)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		_, err := tw.Write(block)
		return err
	})
	if err != nil {
		return err
	}
	return tw.Close()
}

func ErisUnpack(store BlockStore, in io.Reader) error {
	tr := tar.NewReader(in)
	for {
		_, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		block, err := io.ReadAll(tr)
		if err != nil {
			return err
		}
		if err := store.Put(block); err != nil {
			return err
		}
	}
}

func parseConvergenceSecret(s string) ([]byte, error) {
	if s == "" {
		return make([]byte, 32), nil // default 32-byte zero secret
	}
	// if it's a 64 len try as hex string, decode raw 32 bytes directly
	if len(s) == 64 {
		if b, err := hex.DecodeString(s); err == nil {
			return b, nil
		}
	}
	// else derive a deterministic 32-byte secret from the passphrase
	sum := blake2b.Sum256([]byte(s))
	return sum[:], nil
}
func die(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}

func defaultStoreDir() string {
	if dir := os.Getenv("ERIS_STORE"); dir != "" {
		return dir
	}
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = "/tmp"
	}
	return filepath.Join(cacheDir, "eris", "blocks")
}

func printUsage() {
	name := filepath.Base(os.Args[0])
	fmt.Printf(`Usage: %s <command> [options]

Commands:
  encode [options]   Read file from stdin, store blocks, print URN to stdout
                       -block-size int   1024 or 32768 (default 32768)
                       -secret string    64-char hex or passphrase (default: 32 zero bytes)
  decode <URN>       Reconstruct file from store and write to stdout
  pack <URN>         Bundle all blocks for URN into a tar stream on stdout
  unpack [URN]       Import tar block stream from stdin into store (verifies if URN given)

Environment:
  ERIS_STORE         Block directory (default: ~/.cache/eris/blocks)

Examples:
  %s encode < file.txt
  %s decode urn:eris:... > file.txt
  %s pack urn:eris:... | ssh host '%s unpack urn:eris:...'
`, name, name, name, name, name)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(0)
	}

	store, err := NewFSStore(defaultStoreDir())
	if err != nil {
		die(err)
	}

	switch os.Args[1] {
	case "encode":
		fs := flag.NewFlagSet("encode", flag.ExitOnError)
		secretFlag := fs.String("secret", "", "convergence secret (64-char hex or passphrase; default: 32 zero bytes)")
		blockSizeFlag := fs.Int("block-size", 1, "block size in kb (1 or 32)")
		_ = fs.Parse(os.Args[2:])

		if *blockSizeFlag != 1 && *blockSizeFlag != 32 {
			die(fmt.Errorf("invalid block size %d: must be 1 or 32", *blockSizeFlag))
		}
		convergenceSecret, err := parseConvergenceSecret(*secretFlag)
		if err != nil {
			die(err)
		}
		content, err := io.ReadAll(os.Stdin)
		if err != nil {
			die(err)
		}
		cap, blocks, err := ErisEncode(content, convergenceSecret, *blockSizeFlag*1024)
		if err != nil {
			die(err)
		}
		for block := range blocks {
			if err := store.Put([]byte(block)); err != nil {
				die(err)
			}
		}
		urn, err := EncodeURN(cap)
		if err != nil {
			die(err)
		}
		fmt.Println(urn)

	case "decode":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "decode: missing URN\n")
			os.Exit(1)
		}
		cap, err := DecodeURN(os.Args[2])
		if err != nil {
			die(err)
		}
		content, err := ErisDecode(store, cap.block_size, cap.level, cap.root_reference, cap.root_key)
		if err != nil {
			die(err)
		}
		if _, err := os.Stdout.Write(content); err != nil {
			die(err)
		}

	case "pack":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "pack: missing URN\n")
			os.Exit(1)
		}
		if err := ErisPack(store, os.Args[2], os.Stdout); err != nil {
			die(err)
		}

	case "unpack":
		if err := ErisUnpack(store, os.Stdin); err != nil {
			die(err)
		}
		// if user passed a URN, verify all its blocks are now in the store
		if len(os.Args) >= 3 {
			cap, err := DecodeURN(os.Args[2])
			if err != nil {
				die(err)
			}
			if err := CollectBlocks(store, cap.block_size, cap.level, cap.root_reference, cap.root_key, map[string]struct{}{}, func(_, _ []byte) error { return nil }); err != nil {
				die(fmt.Errorf("incomplete archive for URN: %w", err))
			}
		}

	default:
		fmt.Fprintf(os.Stderr, "%s: unknown command\n", os.Args[1])
		os.Exit(1)
	}
}
