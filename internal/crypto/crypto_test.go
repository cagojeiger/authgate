package crypto

import (
	"bytes"
	"testing"
)

func secret(b byte) []byte {
	s := make([]byte, KeySize)
	for i := range s {
		s[i] = b
	}
	return s
}

func mustRoots(t *testing.T) (*Root, *Root) {
	t.Helper()
	enc, err := NewRoot(DomainEnc, "enc-1", secret(0x11))
	if err != nil {
		t.Fatalf("enc root: %v", err)
	}
	lookup, err := NewRoot(DomainLookup, "lkp-1", secret(0x22))
	if err != nil {
		t.Fatalf("lookup root: %v", err)
	}
	return enc, lookup
}

func TestAEAD_RoundTripWithAAD(t *testing.T) {
	key := secret(0x01)
	pt := []byte("person@example.com")
	aad := FieldAAD("user.email", "acct-1", "enc-1", 1)

	ct, nonce, err := Encrypt(key, pt, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Contains(ct, pt) {
		t.Fatal("ciphertext contains plaintext")
	}
	got, err := Decrypt(key, ct, nonce, aad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("decrypt = %q, want %q", got, pt)
	}
}

func TestAEAD_WrongAADFails(t *testing.T) {
	key := secret(0x02)
	ct, nonce, _ := Encrypt(key, []byte("x"), FieldAAD("user.email", "acct-1", "enc-1", 1))
	// Different account_id in AAD must fail authentication.
	if _, err := Decrypt(key, ct, nonce, FieldAAD("user.email", "acct-2", "enc-1", 1)); err == nil {
		t.Fatal("decrypt with mismatched AAD succeeded; want error")
	}
}

func TestAEAD_WrongKeyAndTamperFail(t *testing.T) {
	aad := []byte("aad")
	ct, nonce, _ := Encrypt(secret(0x03), []byte("secret"), aad)
	if _, err := Decrypt(secret(0x04), ct, nonce, aad); err == nil {
		t.Fatal("wrong key decrypt succeeded")
	}
	ct[0] ^= 0xff
	if _, err := Decrypt(secret(0x03), ct, nonce, aad); err == nil {
		t.Fatal("tampered ciphertext decrypt succeeded")
	}
}

func TestEncrypt_FreshNonce(t *testing.T) {
	key := secret(0x05)
	_, n1, _ := Encrypt(key, []byte("x"), nil)
	_, n2, _ := Encrypt(key, []byte("x"), nil)
	if bytes.Equal(n1, n2) {
		t.Fatal("nonce reused across calls")
	}
}

func TestNewRoot_Validation(t *testing.T) {
	if _, err := NewRoot("bogus", "k", secret(0x01)); err == nil {
		t.Fatal("accepted unknown domain")
	}
	if _, err := NewRoot(DomainEnc, "", secret(0x01)); err == nil {
		t.Fatal("accepted empty key_id")
	}
	if _, err := NewRoot(DomainEnc, "k", make([]byte, 16)); err == nil {
		t.Fatal("accepted short secret")
	}
}

func TestSubkey_DeterministicAndSeparated(t *testing.T) {
	enc, _ := mustRoots(t)
	a, err := enc.subkey(LabelPIIField)
	if err != nil {
		t.Fatalf("subkey: %v", err)
	}
	b, _ := enc.subkey(LabelPIIField)
	if !bytes.Equal(a, b) {
		t.Fatal("subkey not deterministic")
	}
	if len(a) != KeySize {
		t.Fatalf("subkey len = %d, want %d", len(a), KeySize)
	}
	// Different label → different subkey (domain separation).
	c, _ := enc.subkey(LabelEncEpochVerify)
	if bytes.Equal(a, c) {
		t.Fatal("different labels produced same subkey")
	}
}

func TestKeys_DomainValidation(t *testing.T) {
	enc, lookup := mustRoots(t)
	if _, err := NewKeys(lookup, enc); err == nil {
		t.Fatal("accepted swapped enc/lookup roots")
	}
	if _, err := NewKeys(enc, lookup); err != nil {
		t.Fatalf("valid roots rejected: %v", err)
	}
}

func TestKeys_LookupHashes(t *testing.T) {
	enc, lookup := mustRoots(t)
	k, _ := NewKeys(enc, lookup)

	// Deterministic.
	sub1 := k.ProviderSubHash("google", "10583")
	sub2 := k.ProviderSubHash("google", "10583")
	if sub1 != sub2 {
		t.Fatal("ProviderSubHash not deterministic")
	}
	// Distinct purposes don't collide on equal input.
	if k.EmailHash("a@b.com") == k.CodeHash("a@b.com") {
		t.Fatal("email and code hash collide (subkey separation broken)")
	}
	// Provider/subject separation: ("google","a:b") vs ("google:a","b") differ.
	if k.ProviderSubHash("google", "a") == k.ProviderSubHash("googl", "ea") {
		t.Fatal("provider-sub message boundary collision")
	}
	// Depends on key material.
	enc2, _ := NewRoot(DomainEnc, "enc-1", secret(0x11))
	lk2, _ := NewRoot(DomainLookup, "lkp-2", secret(0x99))
	k2, _ := NewKeys(enc2, lk2)
	if k.EmailHash("a@b.com") == k2.EmailHash("a@b.com") {
		t.Fatal("email hash ignored lookup root secret")
	}
}

func TestKeys_EncryptDecryptPII(t *testing.T) {
	enc, lookup := mustRoots(t)
	k, _ := NewKeys(enc, lookup)
	aad := FieldAAD("user.email", "acct-1", k.EncKeyID(), 1)

	ct, nonce, err := k.EncryptPII([]byte("hi@x.com"), aad)
	if err != nil {
		t.Fatalf("encrypt pii: %v", err)
	}
	got, err := k.DecryptPII(ct, nonce, aad)
	if err != nil {
		t.Fatalf("decrypt pii: %v", err)
	}
	if string(got) != "hi@x.com" {
		t.Fatalf("pii roundtrip = %q", got)
	}
	if k.EncKeyID() != "enc-1" || k.LookupKeyID() != "lkp-1" {
		t.Fatalf("key ids = %q/%q", k.EncKeyID(), k.LookupKeyID())
	}
}

func TestKeys_VerifyTag(t *testing.T) {
	enc, lookup := mustRoots(t)
	k, _ := NewKeys(enc, lookup)

	encTag, err := k.VerifyTag(DomainEnc)
	if err != nil {
		t.Fatalf("enc verify tag: %v", err)
	}
	lkTag, _ := k.VerifyTag(DomainLookup)
	if encTag == "" || encTag == lkTag {
		t.Fatal("enc/lookup verify tags must be non-empty and distinct")
	}
	// Wrong secret for the same key_id → different tag (startup mismatch detect).
	encBad, _ := NewRoot(DomainEnc, "enc-1", secret(0xab))
	kBad, _ := NewKeys(encBad, lookup)
	badTag, _ := kBad.VerifyTag(DomainEnc)
	if encTag == badTag {
		t.Fatal("verify tag did not change with a different root secret")
	}
	if _, err := k.VerifyTag("bogus"); err == nil {
		t.Fatal("accepted unknown domain")
	}
}
