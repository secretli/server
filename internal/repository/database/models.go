// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.18.0

package database

import (
	"database/sql"
	"time"
)

type Secret struct {
	PublicID       string
	RetrievalToken string
	Nonce          string
	EncryptedData  string
	ExpiresAt      time.Time
	BurnAfterRead  bool
	AlreadyRead    bool
	DeletionToken  sql.NullString
}
