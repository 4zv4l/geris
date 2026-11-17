package main

import (
	"bytes"
	"encoding/base32"
	"fmt"
	"math/bits"
	"slices"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
)

func Pad(input []byte, block_size int) []byte {
	var (
		n      = len(input)
		m      = (block_size - ((n + 1) % block_size)) % block_size
		padded = make([]byte, 0, n+1+m)
		zeroes = make([]byte, m)
	)
	padded = append(padded, input...)
	padded = append(padded, 0x80)
	padded = append(padded, zeroes...)
	return padded
}

func Unpad(input []byte, block_size int) ([]byte, error) {
	if len(input) < block_size || len(input)%block_size != 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	n := len(input)
	for i := range block_size {
		b := input[n-i-1]
		if b == 0x80 {
			return input[:n-i-1], nil
		} else if b == 0x00 {
			continue
		} else {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return nil, fmt.Errorf("invalid padding")
}

type ReadCapabilities struct {
	block_size     int
	level          uint8
	root_reference []byte
	root_key       []byte
}

type ReferencePair struct {
	reference []byte
	key       []byte
}

func ErisEncode(content, convergence_secret []byte, block_size int) (ReadCapabilities, map[string]struct{}, error) {
	if block_size != 1024 && block_size != 32768 {
		return ReadCapabilities{}, nil, fmt.Errorf("invalid ERIS block size: %d", block_size)
	}
	var (
		blocks              = make(map[string]struct{})
		leaf_nodes          = SplitContent(content, block_size)
		reference_key_pairs = []ReferencePair{}
		level               = uint8(0)
	)
	for _, leaf_node := range leaf_nodes {
		block, reference, key, err := EncryptNode(leaf_node, level, convergence_secret)
		if err != nil {
			return ReadCapabilities{}, nil, err
		}
		blocks[string(block)] = struct{}{}
		reference_key_pairs = append(reference_key_pairs, ReferencePair{reference: reference, key: key})
	}
	for len(reference_key_pairs) > 1 {
		if level == 255 {
			return ReadCapabilities{}, nil, fmt.Errorf("maximum tree level exceeded")
		}
		level = level + 1
		nodes := ConstructInternalNodes(reference_key_pairs, block_size)
		reference_key_pairs = nil
		for _, node := range nodes {
			block, reference, key, err := EncryptNode(node, level, convergence_secret)
			if err != nil {
				return ReadCapabilities{}, nil, err
			}
			blocks[string(block)] = struct{}{}
			reference_key_pairs = append(reference_key_pairs, ReferencePair{reference: reference, key: key})
		}
	}
	root := reference_key_pairs[0]
	read_capabilities := ReadCapabilities{block_size, level, root.reference, root.key}
	return read_capabilities, blocks, nil
}

func SplitContent(content []byte, block_size int) [][]byte {
	padded := Pad(content, block_size)
	leaf_nodes := make([][]byte, 0, len(padded)/block_size)
	for i := 0; i < len(padded); i += block_size {
		leaf_nodes = append(leaf_nodes, padded[i:i+block_size:i+block_size])
	}
	return leaf_nodes
}

func EncryptLeafNode(node, convergence_secret []byte) ([]byte, []byte, []byte, error) {
	hash, err := blake2b.New256(convergence_secret)
	if err != nil {
		return nil, nil, nil, err
	}
	hash.Write(node)
	key := hash.Sum(nil)
	nonce := [12]byte{0}
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce[:])
	if err != nil {
		return nil, nil, nil, err
	}
	block := make([]byte, len(node))
	cipher.XORKeyStream(block, node)
	reference := blake2b.Sum256(block)
	return block, reference[:], key, nil
}

func EncryptInternalNode(node []byte, level uint8) ([]byte, []byte, []byte, error) {
	if level == 0 {
		return nil, nil, nil, fmt.Errorf("internal node level must be > 0")
	}
	key := blake2b.Sum256(node)
	nonce := [12]byte{level}
	cipher, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	if err != nil {
		return nil, nil, nil, err
	}
	block := make([]byte, len(node))
	cipher.XORKeyStream(block, node)
	reference := blake2b.Sum256(block)
	return block, reference[:], key[:], nil
}

func EncryptNode(node []byte, level uint8, convergence_secret []byte) ([]byte, []byte, []byte, error) {
	if level == 0 {
		return EncryptLeafNode(node, convergence_secret)
	}
	return EncryptInternalNode(node, level)
}

func ConstructInternalNodes(reference_key_pairs []ReferencePair, block_size int) [][]byte {
	arity := block_size / 64
	if arity <= 0 {
		return nil
	}
	nodes := make([][]byte, 0, (len(reference_key_pairs)+arity-1)/arity)
	for len(reference_key_pairs) > 0 {
		take := min(arity, len(reference_key_pairs))
		batch := reference_key_pairs[:take]
		reference_key_pairs = reference_key_pairs[take:]
		node := make([]byte, block_size)
		for i, pair := range batch {
			offset := i * 64
			copy(node[offset:offset+32], pair.reference)
			copy(node[offset+32:offset+64], pair.key)
		}
		nodes = append(nodes, node)
	}
	return nodes
}

var zeroPair [64]byte

func ErisDecodeRecurse(store BlockStore, block_size int, level uint8, reference, key []byte) ([]byte, error) {
	node, err := DereferenceNode(store, ReferencePair{reference, key}, level, block_size)
	if err != nil {
		return nil, err
	}
	if level == 0 {
		return node, nil
	}
	var output []byte
	for pair := range slices.Chunk(node, 64) {
		if bytes.Equal(pair, zeroPair[:]) {
			break
		}
		chunk, err := ErisDecodeRecurse(store, block_size, level-1, pair[:32], pair[32:])
		if err != nil {
			return nil, err
		}
		output = append(output, chunk...)
	}
	return output, nil
}

func ErisDecode(store BlockStore, block_size int, level uint8, root_reference, root_key []byte) ([]byte, error) {
	if level > 0 {
		if err := VerifyKey(store, block_size, level, root_reference, root_key); err != nil {
			return nil, err
		}
	}
	padded, err := ErisDecodeRecurse(store, block_size, level, root_reference, root_key)
	if err != nil {
		return nil, err
	}
	return Unpad(padded, block_size)
}

func DereferenceNode(store BlockStore, reference_key_pair ReferencePair, level uint8, block_size int) ([]byte, error) {
	block, err := store.Get(reference_key_pair.reference)
	if err != nil {
		return nil, fmt.Errorf("reference is invalid: %w", err)
	}
	if len(block) != block_size {
		return nil, fmt.Errorf("block has invalid size")
	}
	sum := blake2b.Sum256(block)
	if !bytes.Equal(sum[:], reference_key_pair.reference) {
		return nil, fmt.Errorf("block is invalid")
	}
	nonce := [12]byte{level}
	cipher, err := chacha20.NewUnauthenticatedCipher(reference_key_pair.key, nonce[:])
	if err != nil {
		return nil, err
	}
	node := make([]byte, len(block))
	cipher.XORKeyStream(node, block)
	return node, nil
}

func VerifyKey(store BlockStore, block_size int, level uint8, reference, key []byte) error {
	if level == 0 {
		return fmt.Errorf("VerifyKey requires level > 0")
	}
	node, err := DereferenceNode(store, ReferencePair{reference: reference, key: key}, level, block_size)
	if err != nil {
		return err
	}
	sum := blake2b.Sum256(node)
	if !bytes.Equal(sum[:], key) {
		return fmt.Errorf("key in read capability is invalid")
	}
	return nil
}

const erisURNPrefix = "urn:eris:"

var erisBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func EncodeURN(cap ReadCapabilities) (string, error) {
	if cap.block_size != 1024 && cap.block_size != 32768 {
		return "", fmt.Errorf("invalid ERIS block size: %d", cap.block_size)
	}
	if len(cap.root_reference) != 32 || len(cap.root_key) != 32 {
		return "", fmt.Errorf("invalid root reference or key length")
	}

	var buf [66]byte
	buf[0] = uint8(bits.TrailingZeros(uint(cap.block_size)))
	buf[1] = cap.level
	copy(buf[2:34], cap.root_reference)
	copy(buf[34:66], cap.root_key)

	return erisURNPrefix + erisBase32.EncodeToString(buf[:]), nil
}

func DecodeURN(urn string) (ReadCapabilities, error) {
	encoded, ok := strings.CutPrefix(urn, erisURNPrefix)
	if !ok {
		return ReadCapabilities{}, fmt.Errorf("invalid ERIS URN prefix")
	}
	raw, err := erisBase32.DecodeString(strings.ToUpper(encoded))
	if err != nil {
		return ReadCapabilities{}, err
	}
	if len(raw) != 66 {
		return ReadCapabilities{}, fmt.Errorf("invalid capability length: got %d, want 66", len(raw))
	}

	var blockSize int
	switch raw[0] {
	case 10:
		blockSize = 1024
	case 15:
		blockSize = 32768
	default:
		return ReadCapabilities{}, fmt.Errorf("unsupported block size exponent: %d", raw[0])
	}

	return ReadCapabilities{
		block_size:     blockSize,
		level:          raw[1],
		root_reference: raw[2:34],
		root_key:       raw[34:66],
	}, nil
}
