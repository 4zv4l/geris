package main

import (
	"encoding/hex"
	"os"
	"path/filepath"

	"golang.org/x/crypto/blake2b"
)

type BlockStore interface {
	Put(block []byte) error
	Get(reference []byte) ([]byte, error)
}

type FSStore struct {
	Dir string
}

func NewFSStore(dir string) (*FSStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &FSStore{Dir: dir}, nil
}

func (s *FSStore) blockPath(reference []byte) string {
	name := hex.EncodeToString(reference)
	return filepath.Join(s.Dir, name[:2], name[2:])
}

func (s *FSStore) Put(block []byte) error {
	ref := blake2b.Sum256(block)
	path := s.blockPath(ref[:])
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, block, 0o644)
}

func (s *FSStore) Get(reference []byte) ([]byte, error) {
	return os.ReadFile(s.blockPath(reference))
}
