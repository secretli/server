// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/secretli/server/ent/secret"
)

// SecretCreate is the builder for creating a Secret entity.
type SecretCreate struct {
	config
	mutation *SecretMutation
	hooks    []Hook
}

// SetPublicID sets the "public_id" field.
func (sc *SecretCreate) SetPublicID(s string) *SecretCreate {
	sc.mutation.SetPublicID(s)
	return sc
}

// SetRetrievalToken sets the "retrieval_token" field.
func (sc *SecretCreate) SetRetrievalToken(s string) *SecretCreate {
	sc.mutation.SetRetrievalToken(s)
	return sc
}

// SetDeletionToken sets the "deletion_token" field.
func (sc *SecretCreate) SetDeletionToken(s string) *SecretCreate {
	sc.mutation.SetDeletionToken(s)
	return sc
}

// SetNonce sets the "nonce" field.
func (sc *SecretCreate) SetNonce(s string) *SecretCreate {
	sc.mutation.SetNonce(s)
	return sc
}

// SetEncryptedData sets the "encrypted_data" field.
func (sc *SecretCreate) SetEncryptedData(s string) *SecretCreate {
	sc.mutation.SetEncryptedData(s)
	return sc
}

// SetExpiresAt sets the "expires_at" field.
func (sc *SecretCreate) SetExpiresAt(t time.Time) *SecretCreate {
	sc.mutation.SetExpiresAt(t)
	return sc
}

// SetBurnAfterRead sets the "burn_after_read" field.
func (sc *SecretCreate) SetBurnAfterRead(b bool) *SecretCreate {
	sc.mutation.SetBurnAfterRead(b)
	return sc
}

// SetAlreadyRead sets the "already_read" field.
func (sc *SecretCreate) SetAlreadyRead(b bool) *SecretCreate {
	sc.mutation.SetAlreadyRead(b)
	return sc
}

// Mutation returns the SecretMutation object of the builder.
func (sc *SecretCreate) Mutation() *SecretMutation {
	return sc.mutation
}

// Save creates the Secret in the database.
func (sc *SecretCreate) Save(ctx context.Context) (*Secret, error) {
	return withHooks(ctx, sc.sqlSave, sc.mutation, sc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (sc *SecretCreate) SaveX(ctx context.Context) *Secret {
	v, err := sc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (sc *SecretCreate) Exec(ctx context.Context) error {
	_, err := sc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (sc *SecretCreate) ExecX(ctx context.Context) {
	if err := sc.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (sc *SecretCreate) check() error {
	if _, ok := sc.mutation.PublicID(); !ok {
		return &ValidationError{Name: "public_id", err: errors.New(`ent: missing required field "Secret.public_id"`)}
	}
	if _, ok := sc.mutation.RetrievalToken(); !ok {
		return &ValidationError{Name: "retrieval_token", err: errors.New(`ent: missing required field "Secret.retrieval_token"`)}
	}
	if _, ok := sc.mutation.DeletionToken(); !ok {
		return &ValidationError{Name: "deletion_token", err: errors.New(`ent: missing required field "Secret.deletion_token"`)}
	}
	if _, ok := sc.mutation.Nonce(); !ok {
		return &ValidationError{Name: "nonce", err: errors.New(`ent: missing required field "Secret.nonce"`)}
	}
	if _, ok := sc.mutation.EncryptedData(); !ok {
		return &ValidationError{Name: "encrypted_data", err: errors.New(`ent: missing required field "Secret.encrypted_data"`)}
	}
	if _, ok := sc.mutation.ExpiresAt(); !ok {
		return &ValidationError{Name: "expires_at", err: errors.New(`ent: missing required field "Secret.expires_at"`)}
	}
	if _, ok := sc.mutation.BurnAfterRead(); !ok {
		return &ValidationError{Name: "burn_after_read", err: errors.New(`ent: missing required field "Secret.burn_after_read"`)}
	}
	if _, ok := sc.mutation.AlreadyRead(); !ok {
		return &ValidationError{Name: "already_read", err: errors.New(`ent: missing required field "Secret.already_read"`)}
	}
	return nil
}

func (sc *SecretCreate) sqlSave(ctx context.Context) (*Secret, error) {
	if err := sc.check(); err != nil {
		return nil, err
	}
	_node, _spec := sc.createSpec()
	if err := sqlgraph.CreateNode(ctx, sc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	id := _spec.ID.Value.(int64)
	_node.ID = int(id)
	sc.mutation.id = &_node.ID
	sc.mutation.done = true
	return _node, nil
}

func (sc *SecretCreate) createSpec() (*Secret, *sqlgraph.CreateSpec) {
	var (
		_node = &Secret{config: sc.config}
		_spec = sqlgraph.NewCreateSpec(secret.Table, sqlgraph.NewFieldSpec(secret.FieldID, field.TypeInt))
	)
	if value, ok := sc.mutation.PublicID(); ok {
		_spec.SetField(secret.FieldPublicID, field.TypeString, value)
		_node.PublicID = value
	}
	if value, ok := sc.mutation.RetrievalToken(); ok {
		_spec.SetField(secret.FieldRetrievalToken, field.TypeString, value)
		_node.RetrievalToken = value
	}
	if value, ok := sc.mutation.DeletionToken(); ok {
		_spec.SetField(secret.FieldDeletionToken, field.TypeString, value)
		_node.DeletionToken = value
	}
	if value, ok := sc.mutation.Nonce(); ok {
		_spec.SetField(secret.FieldNonce, field.TypeString, value)
		_node.Nonce = value
	}
	if value, ok := sc.mutation.EncryptedData(); ok {
		_spec.SetField(secret.FieldEncryptedData, field.TypeString, value)
		_node.EncryptedData = value
	}
	if value, ok := sc.mutation.ExpiresAt(); ok {
		_spec.SetField(secret.FieldExpiresAt, field.TypeTime, value)
		_node.ExpiresAt = value
	}
	if value, ok := sc.mutation.BurnAfterRead(); ok {
		_spec.SetField(secret.FieldBurnAfterRead, field.TypeBool, value)
		_node.BurnAfterRead = value
	}
	if value, ok := sc.mutation.AlreadyRead(); ok {
		_spec.SetField(secret.FieldAlreadyRead, field.TypeBool, value)
		_node.AlreadyRead = value
	}
	return _node, _spec
}

// SecretCreateBulk is the builder for creating many Secret entities in bulk.
type SecretCreateBulk struct {
	config
	builders []*SecretCreate
}

// Save creates the Secret entities in the database.
func (scb *SecretCreateBulk) Save(ctx context.Context) ([]*Secret, error) {
	specs := make([]*sqlgraph.CreateSpec, len(scb.builders))
	nodes := make([]*Secret, len(scb.builders))
	mutators := make([]Mutator, len(scb.builders))
	for i := range scb.builders {
		func(i int, root context.Context) {
			builder := scb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*SecretMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				var err error
				nodes[i], specs[i] = builder.createSpec()
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, scb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, scb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				if specs[i].ID.Value != nil {
					id := specs[i].ID.Value.(int64)
					nodes[i].ID = int(id)
				}
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, scb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (scb *SecretCreateBulk) SaveX(ctx context.Context) []*Secret {
	v, err := scb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (scb *SecretCreateBulk) Exec(ctx context.Context) error {
	_, err := scb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (scb *SecretCreateBulk) ExecX(ctx context.Context) {
	if err := scb.Exec(ctx); err != nil {
		panic(err)
	}
}
