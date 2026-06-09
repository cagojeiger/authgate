package crypto

import (
	"bytes"
	"testing"
)

func mustKey(t *testing.T, b byte) []byte {
	t.Helper()
	k := make([]byte, KeySize)
	for i := range k {
		k[i] = b
	}
	return k
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key := mustKey(t, 0x01)
	plaintext := []byte("person@example.com")

	ct, nonce, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Contains(ct, plaintext) {
		t.Fatal("ciphertext contains plaintext")
	}
	if len(nonce) != NonceSize {
		t.Fatalf("nonce size = %d, want %d", len(nonce), NonceSize)
	}

	got, err := Decrypt(key, ct, nonce)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypt = %q, want %q", got, plaintext)
	}
}

func TestEncrypt_FreshNoncePerCall(t *testing.T) {
	key := mustKey(t, 0x02)
	_, n1, err := Encrypt(key, []byte("x"))
	if err != nil {
		t.Fatalf("encrypt 1: %v", err)
	}
	_, n2, err := Encrypt(key, []byte("x"))
	if err != nil {
		t.Fatalf("encrypt 2: %v", err)
	}
	if bytes.Equal(n1, n2) {
		t.Fatal("nonce reused across calls")
	}
}

func TestDecrypt_WrongKeyFails(t *testing.T) {
	ct, nonce, err := Encrypt(mustKey(t, 0x03), []byte("secret"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := Decrypt(mustKey(t, 0x04), ct, nonce); err == nil {
		t.Fatal("decrypt with wrong key succeeded; want error")
	}
}

func TestDecrypt_TamperedCiphertextFails(t *testing.T) {
	key := mustKey(t, 0x05)
	ct, nonce, _ := Encrypt(key, []byte("secret"))
	ct[0] ^= 0xff
	if _, err := Decrypt(key, ct, nonce); err == nil {
		t.Fatal("decrypt of tampered ciphertext succeeded; want error")
	}
}

func TestEncrypt_RejectsBadKeySize(t *testing.T) {
	if _, _, err := Encrypt(make([]byte, 16), []byte("x")); err == nil {
		t.Fatal("encrypt accepted 16-byte key; want error")
	}
}

func TestKeyedHash_DeterministicAndSeparated(t *testing.T) {
	pepper := []byte("pepper-value-pepper-value-pepper")
	a := KeyedHash(pepper, "google", "sub-123")
	b := KeyedHash(pepper, "google", "sub-123")
	if a != b {
		t.Fatal("KeyedHash not deterministic")
	}
	// NUL separator: ("a","bc") must not collide with ("ab","c").
	if KeyedHash(pepper, "a", "bc") == KeyedHash(pepper, "ab", "c") {
		t.Fatal("KeyedHash separator collision")
	}
	// Different pepper -> different hash.
	if a == KeyedHash([]byte("other-pepper-other-pepper-other!"), "google", "sub-123") {
		t.Fatal("KeyedHash ignored pepper")
	}
}

func TestMasterKEK_WrapUnwrap(t *testing.T) {
	kek, err := NewMasterKEK(mustKey(t, 0x06), "local", "1")
	if err != nil {
		t.Fatalf("new kek: %v", err)
	}
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("generate dek: %v", err)
	}
	if len(dek) != KeySize {
		t.Fatalf("dek size = %d, want %d", len(dek), KeySize)
	}

	wrapped, err := kek.Wrap(dek)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if bytes.Contains(wrapped, dek) {
		t.Fatal("wrapped dek contains raw dek")
	}

	got, err := kek.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("unwrapped dek mismatch")
	}

	// A different KEK must not unwrap.
	other, _ := NewMasterKEK(mustKey(t, 0x07), "local", "1")
	if _, err := other.Unwrap(wrapped); err == nil {
		t.Fatal("unwrap with wrong KEK succeeded; want error")
	}
}

func TestNewMasterKEK_Validation(t *testing.T) {
	if _, err := NewMasterKEK(make([]byte, 16), "local", "1"); err == nil {
		t.Fatal("accepted short key")
	}
	if _, err := NewMasterKEK(make([]byte, KeySize), "", "1"); err == nil {
		t.Fatal("accepted empty id")
	}
}

func TestKEKProvider_Resolution(t *testing.T) {
	v1, _ := NewMasterKEK(mustKey(t, 0x10), "local", "1")
	v2, _ := NewMasterKEK(mustKey(t, 0x11), "local", "2")
	p, err := NewKEKProvider(v2, v1)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	if p.Current().Version() != "2" {
		t.Fatalf("current version = %q, want 2", p.Current().Version())
	}
	// A DEK wrapped by old v1 must unwrap via ByVersion("1").
	dek, _ := GenerateDEK()
	wrapped, _ := v1.Wrap(dek)
	resolved, err := p.ByVersion("1")
	if err != nil {
		t.Fatalf("by version: %v", err)
	}
	got, err := resolved.Unwrap(wrapped)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap via resolved v1 failed: %v", err)
	}
	if _, err := p.ByVersion("9"); err == nil {
		t.Fatal("unknown KEK version did not error")
	}
}

func TestPepperProvider_HashAndRotation(t *testing.T) {
	p, err := NewPepperProvider("2", map[string][]byte{
		"1": []byte("old-pepper-old-pepper-old-pepper"),
		"2": []byte("new-pepper-new-pepper-new-pepper"),
	})
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	hash, version := p.Hash("normalized@example.com")
	if version != "2" {
		t.Fatalf("hash version = %q, want 2 (current)", version)
	}
	// HashWithVersion("2") must match Hash's output.
	again, err := p.HashWithVersion("2", "normalized@example.com")
	if err != nil {
		t.Fatalf("hash with version: %v", err)
	}
	if hash != again {
		t.Fatal("HashWithVersion(current) != Hash")
	}
	// Old pepper produces a different hash (rotation matching path).
	old, err := p.HashWithVersion("1", "normalized@example.com")
	if err != nil {
		t.Fatalf("hash with old version: %v", err)
	}
	if old == hash {
		t.Fatal("old pepper hash equals current; rotation would be a no-op")
	}
	if _, err := p.HashWithVersion("9", "x"); err == nil {
		t.Fatal("unknown pepper version did not error")
	}
}

func TestNewPepperProvider_Validation(t *testing.T) {
	if _, err := NewPepperProvider("1", map[string][]byte{"2": []byte("k")}); err == nil {
		t.Fatal("accepted current version not present in map")
	}
	if _, err := NewPepperProvider("1", map[string][]byte{"1": nil}); err == nil {
		t.Fatal("accepted empty pepper")
	}
}
