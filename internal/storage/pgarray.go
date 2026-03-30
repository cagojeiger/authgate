package storage

import (
	"database/sql/driver"
	"fmt"
	"strings"
)

// StringArray is a []string that implements sql.Scanner for PostgreSQL text[] columns.
// Works with pgx/v5/stdlib without importing pq.
type StringArray []string

func (a *StringArray) Scan(src any) error {
	if src == nil {
		*a = nil
		return nil
	}

	switch v := src.(type) {
	case string:
		*a = parsePostgresArray(v)
		return nil
	case []byte:
		*a = parsePostgresArray(string(v))
		return nil
	default:
		return fmt.Errorf("StringArray.Scan: unsupported type %T", src)
	}
}

func (a StringArray) Value() (driver.Value, error) {
	if a == nil {
		return nil, nil
	}
	return "{" + strings.Join(a, ",") + "}", nil
}

// parsePostgresArray parses PostgreSQL array literal like {a,b,c}
func parsePostgresArray(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" || s == "{}" {
		return []string{}
	}
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")

	var result []string
	var current strings.Builder
	inQuote := false
	escaped := false

	for _, r := range s {
		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '"' {
			inQuote = !inQuote
			continue
		}
		if r == ',' && !inQuote {
			result = append(result, current.String())
			current.Reset()
			continue
		}
		current.WriteRune(r)
	}
	if current.Len() > 0 {
		result = append(result, current.String())
	}
	return result
}
