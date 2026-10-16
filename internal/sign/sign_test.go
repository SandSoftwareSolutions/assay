package sign

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSignVerify(t *testing.T) {
	pub, priv, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	sig := Sign(priv, "sha256", "root", "ign")
	if !Verify(pub, "sha256", "root", "ign", sig) {
		t.Fatal("valid signature rejected")
	}
	for name, ok := range map[string]bool{
		"other root":      Verify(pub, "sha256", "root2", "ign", sig),
		"other algorithm": Verify(pub, "sha512", "root", "ign", sig),
		"other ignore":    Verify(pub, "sha256", "root", "ign2", sig),
		"garbage":         Verify(pub, "sha256", "root", "ign", "!!!"),
		"empty":           Verify(pub, "sha256", "root", "ign", ""),
	} {
		if ok {
			t.Errorf("%s: signature must not verify", name)
		}
	}
	otherPub, _, _ := Generate()
	if Verify(otherPub, "sha256", "root", "ign", sig) {
		t.Fatal("verified with the wrong key")
	}
}

func TestKeyFilesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := Generate()
	if err := WritePrivate(filepath.Join(dir, "k.key"), priv); err != nil {
		t.Fatal(err)
	}
	if err := WritePublic(filepath.Join(dir, "k.pub"), pub); err != nil {
		t.Fatal(err)
	}
	gotPriv, err := ReadPrivate(filepath.Join(dir, "k.key"))
	if err != nil || !gotPriv.Equal(priv) {
		t.Fatalf("private key: %v", err)
	}
	gotPub, err := ReadPublic(filepath.Join(dir, "k.pub"))
	if err != nil || !gotPub.Equal(pub) {
		t.Fatalf("public key: %v", err)
	}
	if KeyID(pub) != KeyID(gotPub) || len(KeyID(pub)) != 16 {
		t.Fatalf("key id %q", KeyID(pub))
	}
	// A public key file is not a private key file and vice versa.
	if _, err := ReadPrivate(filepath.Join(dir, "k.pub")); err == nil {
		t.Fatal("reading a public key as a private key must fail")
	}
	if _, err := ReadPublic(filepath.Join(dir, "k.key")); err == nil || !strings.Contains(err.Error(), "expected kind") {
		t.Fatalf("got %v", err)
	}
}
