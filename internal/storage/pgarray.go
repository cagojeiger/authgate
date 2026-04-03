package storage

// StringArray is the storage-layer slice type for scopes/redirect URIs/grant types.
// SQL scanning/encoding for postgres arrays is handled in sqlc-generated storeq code.
type StringArray []string
