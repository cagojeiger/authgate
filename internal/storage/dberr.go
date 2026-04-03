package storage

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

const pgUniqueViolationCode = "23505"

func isUniqueViolation(err error, constraintName string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	if pgErr.Code != pgUniqueViolationCode {
		return false
	}
	if constraintName == "" {
		return true
	}
	return pgErr.ConstraintName == constraintName
}
