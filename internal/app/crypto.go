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

	if err := store.EnsureCryptoEpochs(context.Background()); err != nil {
		log.Fatalf("crypto: ensure key epochs: %v", err)
	}
	slog.Info("PII encryption configured",
		"enc_key_id", cfg.EncRootKeyID,
		"lookup_key_id", cfg.LookupRootKeyID,
	)
}
