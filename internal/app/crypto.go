package app

import (
	"context"
	"encoding/base64"
	"log"
	"log/slog"

	"github.com/kangheeyong/authgate/internal/config"
	"github.com/kangheeyong/authgate/internal/crypto"
	"github.com/kangheeyong/authgate/internal/storage"
)

// mustSetupCrypto wires PII at-rest encryption (ADR-002) when the env roots are
// configured: it derives the domain subkeys and ensures/verifies the active
// crypto_key_epochs rows. When the roots are unset, encryption stays inert and
// authgate runs unchanged. Any misconfiguration (bad base64, wrong secret for a
// registered key_id, runtime key_id change) fails startup before serving.
func mustSetupCrypto(cfg *config.Config, store *storage.Storage) {
	if cfg.EncRootSecret == "" {
		return // roots unset → encryption inert
	}

	encSecret, err := base64.StdEncoding.DecodeString(cfg.EncRootSecret)
	if err != nil {
		log.Fatalf("crypto: PII_ENC_ROOT_SECRET must be base64: %v", err)
	}
	lookupSecret, err := base64.StdEncoding.DecodeString(cfg.LookupRootSecret)
	if err != nil {
		log.Fatalf("crypto: PII_LOOKUP_ROOT_SECRET must be base64: %v", err)
	}

	encRoot, err := crypto.NewRoot(crypto.DomainEnc, cfg.EncRootKeyID, encSecret)
	if err != nil {
		log.Fatalf("crypto: enc root: %v", err)
	}
	lookupRoot, err := crypto.NewRoot(crypto.DomainLookup, cfg.LookupRootKeyID, lookupSecret)
	if err != nil {
		log.Fatalf("crypto: lookup root: %v", err)
	}

	keys, err := crypto.NewKeys(encRoot, lookupRoot)
	if err != nil {
		log.Fatalf("crypto: derive subkeys: %v", err)
	}
	store.SetKeys(keys)

	ctx := context.Background()
	if err := store.EnsureCryptoEpochs(ctx); err != nil {
		log.Fatalf("crypto: ensure key epochs: %v", err)
	}
	slog.Info("PII encryption configured",
		"enc_key_id", cfg.EncRootKeyID,
		"lookup_key_id", cfg.LookupRootKeyID,
	)

	// Backfill legacy plaintext provider subjects into encrypted columns. With
	// keys configured, lookups go through provider_sub_hash, so any row not yet
	// backfilled would be unfindable — backfill must complete before serving.
	n, err := store.BackfillProviderSub(ctx)
	if err != nil {
		log.Fatalf("crypto: provider_sub backfill: %v", err)
	}
	if n > 0 {
		slog.Info("provider_sub backfill complete", "rows", n)
	}

	m, err := store.BackfillUserPII(ctx)
	if err != nil {
		log.Fatalf("crypto: user PII backfill: %v", err)
	}
	if m > 0 {
		slog.Info("user PII backfill complete", "rows", m)
	}
}
