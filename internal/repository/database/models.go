// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.13.0

package database

import (
	"time"
)

type Secret struct {
	PublicID       string
	RetrievalToken string
	Nonce          string
	EncryptedData  string
	ExpiresAt      time.Time
}
