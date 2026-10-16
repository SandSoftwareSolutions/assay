// Package sign signs and verifies manifest root hashes with Ed25519.
//
// A signature turns "the files match the manifest" into "the files match what the key holder sealed":
// without it, whoever can change the files can also replace the manifest.
package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	privateHeader = "hallmark-ed25519-private-key:"
	publicHeader  = "hallmark-ed25519-public-key:"
	// Algorithm is the signature algorithm name stored in manifests.
	Algorithm = "ed25519"
)

// Generate creates a new key pair.
func Generate() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// KeyID is a short identifier of a public key (the first 8 bytes of its SHA-256, hex).
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// message is what is signed: a version tag, the hash algorithm, the root hash over all files and a
// digest of the ignore patterns (so patterns cannot be added later to hide files).
func message(algorithm, root, ignoreDigest string) []byte {
	return []byte("hallmark/1\n" + algorithm + "\n" + root + "\n" + ignoreDigest + "\n")
}

// Sign signs a root hash together with the ignore digest.
func Sign(priv ed25519.PrivateKey, algorithm, root, ignoreDigest string) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, message(algorithm, root, ignoreDigest)))
}

// Verify checks a signature.
func Verify(pub ed25519.PublicKey, algorithm, root, ignoreDigest, signature string) bool {
	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, message(algorithm, root, ignoreDigest), raw)
}

// WritePrivate stores a private key (owner-only permissions where the system supports it).
func WritePrivate(path string, priv ed25519.PrivateKey) error {
	body := privateHeader + " " + base64.StdEncoding.EncodeToString(priv.Seed()) + "\n"
	return os.WriteFile(path, []byte(body), 0o600)
}

// WritePublic stores a public key.
func WritePublic(path string, pub ed25519.PublicKey) error {
	body := publicHeader + " " + base64.StdEncoding.EncodeToString(pub) + "\n"
	return os.WriteFile(path, []byte(body), 0o644)
}

func readKeyFile(path, header string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	line := strings.TrimSpace(string(data))
	if !strings.HasPrefix(line, header) {
		return nil, fmt.Errorf("%s is not a hallmark key file of the expected kind", path)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(line, header)))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return raw, nil
}

// ReadPrivate loads a private key file.
func ReadPrivate(path string) (ed25519.PrivateKey, error) {
	raw, err := readKeyFile(path, privateHeader)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.SeedSize {
		return nil, errors.New("private key has the wrong length")
	}
	return ed25519.NewKeyFromSeed(raw), nil
}

// ReadPublic loads a public key file.
func ReadPublic(path string) (ed25519.PublicKey, error) {
	raw, err := readKeyFile(path, publicHeader)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("public key has the wrong length")
	}
	return ed25519.PublicKey(raw), nil
}
