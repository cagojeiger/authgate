package crypto

import (
	"errors"
	"fmt"
)

// KEKProvider resolves KEKs by version. New DEKs are wrapped with Current(), and
// existing DEKs are unwrapped by the exact version that wrapped them. Old KEK
// versions stay available for unwrap/rewrap during rotation (decrypt-any,
// write-latest).
type KEKProvider struct {
	current   string
	byVersion map[string]KEK
}

// NewKEKProvider registers the current KEK plus any older versions kept for
// unwrap during rotation.
func NewKEKProvider(current KEK, older ...KEK) (*KEKProvider, error) {
	if current == nil {
		return nil, errors.New("crypto: current KEK is required")
	}
	p := &KEKProvider{current: current.Version(), byVersion: map[string]KEK{}}
	p.byVersion[current.Version()] = current
	for _, k := range older {
		if k != nil {
			p.byVersion[k.Version()] = k
		}
	}
	return p, nil
}

// Current returns the KEK used to wrap new DEKs.
func (p *KEKProvider) Current() KEK { return p.byVersion[p.current] }

// ByVersion returns the KEK for a stored kek_version, or an error if unknown.
func (p *KEKProvider) ByVersion(version string) (KEK, error) {
	k, ok := p.byVersion[version]
	if !ok {
		return nil, fmt.Errorf("crypto: unknown KEK version %q", version)
	}
	return k, nil
}

// PepperProvider resolves HMAC peppers by version. New hashes use the current
// pepper; lookups may verify against any known version during pepper rotation.
type PepperProvider struct {
	current   string
	byVersion map[string][]byte
}

// NewPepperProvider registers peppers keyed by version and marks one current.
func NewPepperProvider(currentVersion string, peppers map[string][]byte) (*PepperProvider, error) {
	if currentVersion == "" {
		return nil, errors.New("crypto: current pepper version is required")
	}
	if _, ok := peppers[currentVersion]; !ok {
		return nil, fmt.Errorf("crypto: current pepper version %q not present", currentVersion)
	}
	cp := make(map[string][]byte, len(peppers))
	for v, key := range peppers {
		if len(key) == 0 {
			return nil, fmt.Errorf("crypto: empty pepper for version %q", v)
		}
		cp[v] = key
	}
	return &PepperProvider{current: currentVersion, byVersion: cp}, nil
}

// Hash computes the keyed hash with the current pepper and returns the version
// used, so callers can persist it for later verification or rehash.
func (p *PepperProvider) Hash(parts ...string) (hash, version string) {
	return KeyedHash(p.byVersion[p.current], parts...), p.current
}

// HashWithVersion computes the keyed hash under a specific pepper version, used
// to match rows written under an older pepper during rotation.
func (p *PepperProvider) HashWithVersion(version string, parts ...string) (string, error) {
	key, ok := p.byVersion[version]
	if !ok {
		return "", fmt.Errorf("crypto: unknown pepper version %q", version)
	}
	return KeyedHash(key, parts...), nil
}

// CurrentVersion reports the version new hashes are written under.
func (p *PepperProvider) CurrentVersion() string { return p.current }
