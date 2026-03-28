package service

import (
	"authgate/internal/storage"
)

// Compile-time interface compliance checks
// These ensure that *storage.DB implements all the store interfaces

var (
	_ SessionStore      = (*storage.DB)(nil)
	_ UserStore         = (*storage.DB)(nil)
	_ AuthCodeStore     = (*storage.DB)(nil)
	_ RefreshTokenStore = (*storage.DB)(nil)
	_ Pinger            = (*storage.DB)(nil)
	_ Store             = (*storage.DB)(nil)
)
