// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/secretli/server/ent/secret"
)

// Secret is the model entity for the Secret schema.
type Secret struct {
	config `json:"-"`
	// ID of the ent.
	ID int `json:"id,omitempty"`
	// PublicID holds the value of the "public_id" field.
	PublicID string `json:"public_id,omitempty"`
	// RetrievalToken holds the value of the "retrieval_token" field.
	RetrievalToken string `json:"retrieval_token,omitempty"`
	// DeletionToken holds the value of the "deletion_token" field.
	DeletionToken string `json:"deletion_token,omitempty"`
	// Nonce holds the value of the "nonce" field.
	Nonce string `json:"nonce,omitempty"`
	// EncryptedData holds the value of the "encrypted_data" field.
	EncryptedData string `json:"encrypted_data,omitempty"`
	// ExpiresAt holds the value of the "expires_at" field.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	// BurnAfterRead holds the value of the "burn_after_read" field.
	BurnAfterRead bool `json:"burn_after_read,omitempty"`
	// AlreadyRead holds the value of the "already_read" field.
	AlreadyRead  bool `json:"already_read,omitempty"`
	selectValues sql.SelectValues
}

// scanValues returns the types for scanning values from sql.Rows.
func (*Secret) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case secret.FieldBurnAfterRead, secret.FieldAlreadyRead:
			values[i] = new(sql.NullBool)
		case secret.FieldID:
			values[i] = new(sql.NullInt64)
		case secret.FieldPublicID, secret.FieldRetrievalToken, secret.FieldDeletionToken, secret.FieldNonce, secret.FieldEncryptedData:
			values[i] = new(sql.NullString)
		case secret.FieldExpiresAt:
			values[i] = new(sql.NullTime)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the Secret fields.
func (s *Secret) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case secret.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			s.ID = int(value.Int64)
		case secret.FieldPublicID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field public_id", values[i])
			} else if value.Valid {
				s.PublicID = value.String
			}
		case secret.FieldRetrievalToken:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field retrieval_token", values[i])
			} else if value.Valid {
				s.RetrievalToken = value.String
			}
		case secret.FieldDeletionToken:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field deletion_token", values[i])
			} else if value.Valid {
				s.DeletionToken = value.String
			}
		case secret.FieldNonce:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field nonce", values[i])
			} else if value.Valid {
				s.Nonce = value.String
			}
		case secret.FieldEncryptedData:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field encrypted_data", values[i])
			} else if value.Valid {
				s.EncryptedData = value.String
			}
		case secret.FieldExpiresAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field expires_at", values[i])
			} else if value.Valid {
				s.ExpiresAt = value.Time
			}
		case secret.FieldBurnAfterRead:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field burn_after_read", values[i])
			} else if value.Valid {
				s.BurnAfterRead = value.Bool
			}
		case secret.FieldAlreadyRead:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field already_read", values[i])
			} else if value.Valid {
				s.AlreadyRead = value.Bool
			}
		default:
			s.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the Secret.
// This includes values selected through modifiers, order, etc.
func (s *Secret) Value(name string) (ent.Value, error) {
	return s.selectValues.Get(name)
}

// Update returns a builder for updating this Secret.
// Note that you need to call Secret.Unwrap() before calling this method if this Secret
// was returned from a transaction, and the transaction was committed or rolled back.
func (s *Secret) Update() *SecretUpdateOne {
	return NewSecretClient(s.config).UpdateOne(s)
}

// Unwrap unwraps the Secret entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (s *Secret) Unwrap() *Secret {
	_tx, ok := s.config.driver.(*txDriver)
	if !ok {
		panic("ent: Secret is not a transactional entity")
	}
	s.config.driver = _tx.drv
	return s
}

// String implements the fmt.Stringer.
func (s *Secret) String() string {
	var builder strings.Builder
	builder.WriteString("Secret(")
	builder.WriteString(fmt.Sprintf("id=%v, ", s.ID))
	builder.WriteString("public_id=")
	builder.WriteString(s.PublicID)
	builder.WriteString(", ")
	builder.WriteString("retrieval_token=")
	builder.WriteString(s.RetrievalToken)
	builder.WriteString(", ")
	builder.WriteString("deletion_token=")
	builder.WriteString(s.DeletionToken)
	builder.WriteString(", ")
	builder.WriteString("nonce=")
	builder.WriteString(s.Nonce)
	builder.WriteString(", ")
	builder.WriteString("encrypted_data=")
	builder.WriteString(s.EncryptedData)
	builder.WriteString(", ")
	builder.WriteString("expires_at=")
	builder.WriteString(s.ExpiresAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("burn_after_read=")
	builder.WriteString(fmt.Sprintf("%v", s.BurnAfterRead))
	builder.WriteString(", ")
	builder.WriteString("already_read=")
	builder.WriteString(fmt.Sprintf("%v", s.AlreadyRead))
	builder.WriteByte(')')
	return builder.String()
}

// Secrets is a parsable slice of Secret.
type Secrets []*Secret
