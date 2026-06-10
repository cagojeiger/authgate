package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// Keys holds the HKDF-derived purpose subkeys for both domains, built once at
// startup from the env roots. It exposes the high-level PII encrypt/decrypt,
// lookup-hash, and epoch verify_tag operations. Subkeys never leave this struct.
type Keys struct {
	encKeyID    string
	lookupKeyID string

	piiField          []byte
	encEpochVerify    []byte
	lookupEpochVerify []byte
	providerSub       []byte
	email             []byte
	code              []byte
	session           []byte
}

// NewKeys derives every purpose subkey from the enc and lookup roots.
func NewKeys(enc, lookup *Root) (*Keys, error) {
	if enc == nil || lookup == nil {
		return nil, errors.New("crypto: enc and lookup roots are required")
	}
	if enc.domain != DomainEnc {
		return nil, fmt.Errorf("crypto: enc root has domain %q, want enc", enc.domain)
	}
	if lookup.domain != DomainLookup {
		return nil, fmt.Errorf("crypto: lookup root has domain %q, want lookup", lookup.domain)
	}

	k := &Keys{encKeyID: enc.keyID, lookupKeyID: lookup.keyID}
	var err error
	derive := func(r *Root, label string, dst *[]byte) {
		if err != nil {
			return
		}
		*dst, err = r.subkey(label)
	}
	derive(enc, LabelPIIField, &k.piiField)
	derive(enc, LabelEncEpochVerify, &k.encEpochVerify)
	derive(lookup, LabelLookupEpochVerify, &k.lookupEpochVerify)
	derive(lookup, LabelProviderSub, &k.providerSub)
	derive(lookup, LabelEmail, &k.email)
	derive(lookup, LabelCode, &k.code)
	derive(lookup, LabelSession, &k.session)
	if err != nil {
		return nil, err
	}
	return k, nil
}

// EncKeyID / LookupKeyID report which epoch (key_id) these subkeys belong to,
// so callers can persist key_id alongside each ciphertext/hash.
func (k *Keys) EncKeyID() string    { return k.encKeyID }
func (k *Keys) LookupKeyID() string { return k.lookupKeyID }

// EncryptPII seals plaintext PII under the enc-domain field subkey, binding aad.
func (k *Keys) EncryptPII(plaintext, aad []byte) (ciphertext, nonce []byte, err error) {
	return Encrypt(k.piiField, plaintext, aad)
}

// DecryptPII reverses EncryptPII with the same aad.
func (k *Keys) DecryptPII(ciphertext, nonce, aad []byte) ([]byte, error) {
	return Decrypt(k.piiField, ciphertext, nonce, aad)
}

// ProviderSubHash returns the lookup HMAC for an OAuth provider subject.
func (k *Keys) ProviderSubHash(provider, subject string) string {
	return hmacHex(k.providerSub, "provider-sub:v1:"+provider+":"+subject)
}

// EmailHash returns the lookup HMAC for a normalized email.
func (k *Keys) EmailHash(normalizedEmail string) string {
	return hmacHex(k.email, "email:v1:"+normalizedEmail)
}

// CodeHash returns the lookup HMAC for a short-lived code (device/user/authz).
func (k *Keys) CodeHash(code string) string {
	return hmacHex(k.code, "code:v1:"+code)
}

// SessionHash returns the lookup HMAC for a session bearer token.
func (k *Keys) SessionHash(token string) string {
	return hmacHex(k.session, "session:v1:"+token)
}

// VerifyTag computes the crypto_key_epochs verify_tag for the given domain,
// using that domain's epoch-verify subkey and key_id. Startup compares this
// against the stored tag to detect a wrong root secret injected for a key_id.
func (k *Keys) VerifyTag(domain string) (string, error) {
	switch domain {
	case DomainEnc:
		return hmacHex(k.encEpochVerify, "key-epoch:v1:"+DomainEnc+":"+k.encKeyID), nil
	case DomainLookup:
		return hmacHex(k.lookupEpochVerify, "key-epoch:v1:"+DomainLookup+":"+k.lookupKeyID), nil
	default:
		return "", fmt.Errorf("crypto: unknown domain %q", domain)
	}
}

// FieldAAD builds the stable additional-authenticated-data string that binds a
// PII ciphertext to its storage context. It must be reconstructable at decrypt
// time, so it uses only stable values (field id, account id, key id, version).
func FieldAAD(field, accountID, keyID string, version int) []byte {
	return []byte(fmt.Sprintf("app=authgate;field=%s;account_id=%s;key_id=%s;version=%d", field, accountID, keyID, version))
}

func hmacHex(subkey []byte, msg string) string {
	mac := hmac.New(sha256.New, subkey)
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}
