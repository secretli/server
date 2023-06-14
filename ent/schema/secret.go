package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// Secret holds the schema definition for the Secret entity.
type Secret struct {
	ent.Schema
}

// Fields of the Secret.
func (Secret) Fields() []ent.Field {
	return []ent.Field{
		field.String("public_id").Unique(),
		field.String("retrieval_token"),
		field.String("deletion_token"),
		field.String("nonce"),
		field.String("encrypted_data"),
		field.Time("expires_at"),
		field.Bool("burn_after_read"),
		field.Bool("already_read"),
	}
}

// Edges of the Secret.
func (Secret) Edges() []ent.Edge {
	return nil
}
