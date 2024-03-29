// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/secretli/server/ent/predicate"
	"github.com/secretli/server/ent/secret"
)

// SecretUpdate is the builder for updating Secret entities.
type SecretUpdate struct {
	config
	hooks    []Hook
	mutation *SecretMutation
}

// Where appends a list predicates to the SecretUpdate builder.
func (su *SecretUpdate) Where(ps ...predicate.Secret) *SecretUpdate {
	su.mutation.Where(ps...)
	return su
}

// SetPublicID sets the "public_id" field.
func (su *SecretUpdate) SetPublicID(s string) *SecretUpdate {
	su.mutation.SetPublicID(s)
	return su
}

// SetRetrievalToken sets the "retrieval_token" field.
func (su *SecretUpdate) SetRetrievalToken(s string) *SecretUpdate {
	su.mutation.SetRetrievalToken(s)
	return su
}

// SetDeletionToken sets the "deletion_token" field.
func (su *SecretUpdate) SetDeletionToken(s string) *SecretUpdate {
	su.mutation.SetDeletionToken(s)
	return su
}

// SetNonce sets the "nonce" field.
func (su *SecretUpdate) SetNonce(s string) *SecretUpdate {
	su.mutation.SetNonce(s)
	return su
}

// SetEncryptedData sets the "encrypted_data" field.
func (su *SecretUpdate) SetEncryptedData(s string) *SecretUpdate {
	su.mutation.SetEncryptedData(s)
	return su
}

// SetExpiresAt sets the "expires_at" field.
func (su *SecretUpdate) SetExpiresAt(t time.Time) *SecretUpdate {
	su.mutation.SetExpiresAt(t)
	return su
}

// SetBurnAfterRead sets the "burn_after_read" field.
func (su *SecretUpdate) SetBurnAfterRead(b bool) *SecretUpdate {
	su.mutation.SetBurnAfterRead(b)
	return su
}

// SetAlreadyRead sets the "already_read" field.
func (su *SecretUpdate) SetAlreadyRead(b bool) *SecretUpdate {
	su.mutation.SetAlreadyRead(b)
	return su
}

// Mutation returns the SecretMutation object of the builder.
func (su *SecretUpdate) Mutation() *SecretMutation {
	return su.mutation
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (su *SecretUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, su.sqlSave, su.mutation, su.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (su *SecretUpdate) SaveX(ctx context.Context) int {
	affected, err := su.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (su *SecretUpdate) Exec(ctx context.Context) error {
	_, err := su.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (su *SecretUpdate) ExecX(ctx context.Context) {
	if err := su.Exec(ctx); err != nil {
		panic(err)
	}
}

func (su *SecretUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := sqlgraph.NewUpdateSpec(secret.Table, secret.Columns, sqlgraph.NewFieldSpec(secret.FieldID, field.TypeInt))
	if ps := su.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := su.mutation.PublicID(); ok {
		_spec.SetField(secret.FieldPublicID, field.TypeString, value)
	}
	if value, ok := su.mutation.RetrievalToken(); ok {
		_spec.SetField(secret.FieldRetrievalToken, field.TypeString, value)
	}
	if value, ok := su.mutation.DeletionToken(); ok {
		_spec.SetField(secret.FieldDeletionToken, field.TypeString, value)
	}
	if value, ok := su.mutation.Nonce(); ok {
		_spec.SetField(secret.FieldNonce, field.TypeString, value)
	}
	if value, ok := su.mutation.EncryptedData(); ok {
		_spec.SetField(secret.FieldEncryptedData, field.TypeString, value)
	}
	if value, ok := su.mutation.ExpiresAt(); ok {
		_spec.SetField(secret.FieldExpiresAt, field.TypeTime, value)
	}
	if value, ok := su.mutation.BurnAfterRead(); ok {
		_spec.SetField(secret.FieldBurnAfterRead, field.TypeBool, value)
	}
	if value, ok := su.mutation.AlreadyRead(); ok {
		_spec.SetField(secret.FieldAlreadyRead, field.TypeBool, value)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, su.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{secret.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	su.mutation.done = true
	return n, nil
}

// SecretUpdateOne is the builder for updating a single Secret entity.
type SecretUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *SecretMutation
}

// SetPublicID sets the "public_id" field.
func (suo *SecretUpdateOne) SetPublicID(s string) *SecretUpdateOne {
	suo.mutation.SetPublicID(s)
	return suo
}

// SetRetrievalToken sets the "retrieval_token" field.
func (suo *SecretUpdateOne) SetRetrievalToken(s string) *SecretUpdateOne {
	suo.mutation.SetRetrievalToken(s)
	return suo
}

// SetDeletionToken sets the "deletion_token" field.
func (suo *SecretUpdateOne) SetDeletionToken(s string) *SecretUpdateOne {
	suo.mutation.SetDeletionToken(s)
	return suo
}

// SetNonce sets the "nonce" field.
func (suo *SecretUpdateOne) SetNonce(s string) *SecretUpdateOne {
	suo.mutation.SetNonce(s)
	return suo
}

// SetEncryptedData sets the "encrypted_data" field.
func (suo *SecretUpdateOne) SetEncryptedData(s string) *SecretUpdateOne {
	suo.mutation.SetEncryptedData(s)
	return suo
}

// SetExpiresAt sets the "expires_at" field.
func (suo *SecretUpdateOne) SetExpiresAt(t time.Time) *SecretUpdateOne {
	suo.mutation.SetExpiresAt(t)
	return suo
}

// SetBurnAfterRead sets the "burn_after_read" field.
func (suo *SecretUpdateOne) SetBurnAfterRead(b bool) *SecretUpdateOne {
	suo.mutation.SetBurnAfterRead(b)
	return suo
}

// SetAlreadyRead sets the "already_read" field.
func (suo *SecretUpdateOne) SetAlreadyRead(b bool) *SecretUpdateOne {
	suo.mutation.SetAlreadyRead(b)
	return suo
}

// Mutation returns the SecretMutation object of the builder.
func (suo *SecretUpdateOne) Mutation() *SecretMutation {
	return suo.mutation
}

// Where appends a list predicates to the SecretUpdate builder.
func (suo *SecretUpdateOne) Where(ps ...predicate.Secret) *SecretUpdateOne {
	suo.mutation.Where(ps...)
	return suo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (suo *SecretUpdateOne) Select(field string, fields ...string) *SecretUpdateOne {
	suo.fields = append([]string{field}, fields...)
	return suo
}

// Save executes the query and returns the updated Secret entity.
func (suo *SecretUpdateOne) Save(ctx context.Context) (*Secret, error) {
	return withHooks(ctx, suo.sqlSave, suo.mutation, suo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (suo *SecretUpdateOne) SaveX(ctx context.Context) *Secret {
	node, err := suo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (suo *SecretUpdateOne) Exec(ctx context.Context) error {
	_, err := suo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (suo *SecretUpdateOne) ExecX(ctx context.Context) {
	if err := suo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (suo *SecretUpdateOne) sqlSave(ctx context.Context) (_node *Secret, err error) {
	_spec := sqlgraph.NewUpdateSpec(secret.Table, secret.Columns, sqlgraph.NewFieldSpec(secret.FieldID, field.TypeInt))
	id, ok := suo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "Secret.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := suo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, secret.FieldID)
		for _, f := range fields {
			if !secret.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != secret.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := suo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := suo.mutation.PublicID(); ok {
		_spec.SetField(secret.FieldPublicID, field.TypeString, value)
	}
	if value, ok := suo.mutation.RetrievalToken(); ok {
		_spec.SetField(secret.FieldRetrievalToken, field.TypeString, value)
	}
	if value, ok := suo.mutation.DeletionToken(); ok {
		_spec.SetField(secret.FieldDeletionToken, field.TypeString, value)
	}
	if value, ok := suo.mutation.Nonce(); ok {
		_spec.SetField(secret.FieldNonce, field.TypeString, value)
	}
	if value, ok := suo.mutation.EncryptedData(); ok {
		_spec.SetField(secret.FieldEncryptedData, field.TypeString, value)
	}
	if value, ok := suo.mutation.ExpiresAt(); ok {
		_spec.SetField(secret.FieldExpiresAt, field.TypeTime, value)
	}
	if value, ok := suo.mutation.BurnAfterRead(); ok {
		_spec.SetField(secret.FieldBurnAfterRead, field.TypeBool, value)
	}
	if value, ok := suo.mutation.AlreadyRead(); ok {
		_spec.SetField(secret.FieldAlreadyRead, field.TypeBool, value)
	}
	_node = &Secret{config: suo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, suo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{secret.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	suo.mutation.done = true
	return _node, nil
}
