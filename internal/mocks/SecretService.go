// Code generated by mockery v2.30.1. DO NOT EDIT.

package mocks

import (
	context "context"

	internal "github.com/secretli/server/internal"
	mock "github.com/stretchr/testify/mock"
)

// SecretService is an autogenerated mock type for the SecretService type
type SecretService struct {
	mock.Mock
}

// Delete provides a mock function with given fields: ctx, publicID, retrievalToken, deletionToken
func (_m *SecretService) Delete(ctx context.Context, publicID string, retrievalToken string, deletionToken string) error {
	ret := _m.Called(ctx, publicID, retrievalToken, deletionToken)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) error); ok {
		r0 = rf(ctx, publicID, retrievalToken, deletionToken)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Retrieve provides a mock function with given fields: ctx, publicID, token
func (_m *SecretService) Retrieve(ctx context.Context, publicID string, token string) (internal.Secret, error) {
	ret := _m.Called(ctx, publicID, token)

	var r0 internal.Secret
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (internal.Secret, error)); ok {
		return rf(ctx, publicID, token)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) internal.Secret); ok {
		r0 = rf(ctx, publicID, token)
	} else {
		r0 = ret.Get(0).(internal.Secret)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, publicID, token)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Store provides a mock function with given fields: ctx, secret
func (_m *SecretService) Store(ctx context.Context, secret internal.Secret) error {
	ret := _m.Called(ctx, secret)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, internal.Secret) error); ok {
		r0 = rf(ctx, secret)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewSecretService creates a new instance of SecretService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewSecretService(t interface {
	mock.TestingT
	Cleanup(func())
}) *SecretService {
	mock := &SecretService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
