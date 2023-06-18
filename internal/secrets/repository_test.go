package secrets

import (
	"context"
	"github.com/secretli/server/ent/enttest"
	"github.com/secretli/server/internal"
	"github.com/secretli/server/internal/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func TestRepository_Get(t *testing.T) {
	ctx := context.Background()

	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()

	sut := NewRepository(client)

	_, err := sut.Get(ctx, "testing-public-id")
	assert.ErrorIs(t, err, internal.ErrUnknownSecret)

	err = sut.Store(ctx, internal.Secret{PublicID: "testing-public-id"})
	assert.NoError(t, err)

	secret, err := sut.Get(ctx, "testing-public-id")
	assert.NoError(t, err)
	assert.EqualValues(t, "testing-public-id", secret.PublicID)
}

func TestRepository_Store(t *testing.T) {
	ctx := context.Background()

	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()

	sut := NewRepository(client)

	_, err := sut.Get(ctx, "testing-public-id")
	assert.ErrorIs(t, err, internal.ErrUnknownSecret)

	err = sut.Store(ctx, internal.Secret{PublicID: "testing-public-id"})
	assert.NoError(t, err)

	secret, err := sut.Get(ctx, "testing-public-id")
	assert.NoError(t, err)
	assert.EqualValues(t, "testing-public-id", secret.PublicID)
}

func TestRepository_MarkAsRead(t *testing.T) {
	ctx := context.Background()

	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()

	sut := NewRepository(client)

	err := sut.Store(ctx, internal.Secret{PublicID: "testing-public-id"})
	assert.NoError(t, err)

	err = sut.MarkAsRead(ctx, "testing-public-id")
	assert.NoError(t, err)

	secret, err := sut.Get(ctx, "testing-public-id")
	assert.NoError(t, err)
	assert.True(t, secret.AlreadyRead)
}

func TestRepository_Delete(t *testing.T) {
	ctx := context.Background()

	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()

	sut := NewRepository(client)

	err := sut.Delete(ctx, "testing-public-id")
	assert.NoError(t, err)

	err = sut.Store(ctx, internal.Secret{PublicID: "testing-public-id"})
	assert.NoError(t, err)

	err = sut.Delete(ctx, "testing-public-id")
	assert.NoError(t, err)

	_, err = sut.Get(ctx, "testing-public-id")
	assert.ErrorIs(t, err, internal.ErrUnknownSecret)
}

func TestRepository_Cleanup(t *testing.T) {
	ctx := context.Background()

	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()

	sut := NewRepository(client)

	now := time.Now()
	past := now.Add(-5 * time.Second)
	future := now.Add(10 * time.Minute)

	_ = sut.Store(ctx, internal.Secret{PublicID: "id-1", ExpiresAt: past})
	_ = sut.Store(ctx, internal.Secret{PublicID: "id-2", ExpiresAt: future})
	_ = sut.Store(ctx, internal.Secret{PublicID: "id-3", ExpiresAt: future, BurnAfterRead: true, AlreadyRead: false})
	_ = sut.Store(ctx, internal.Secret{PublicID: "id-4", ExpiresAt: future, BurnAfterRead: true, AlreadyRead: true})
	_ = sut.Store(ctx, internal.Secret{PublicID: "id-5", ExpiresAt: past, BurnAfterRead: true, AlreadyRead: false})

	err := sut.Cleanup(ctx, now)
	assert.NoError(t, err)

	secrets, err := client.Secret.Query().All(ctx)
	assert.NoError(t, err)
	assert.Len(t, secrets, 2)

	expectedSurvivors := []string{"id-2", "id-3"}
	assert.Contains(t, expectedSurvivors, secrets[0].PublicID)
	assert.Contains(t, expectedSurvivors, secrets[1].PublicID)
}

func TestRepository_StartCleanupJob(t *testing.T) {
	ctx := context.Background()
	ticker := make(chan time.Time)

	clock := mocks.NewClock(t)
	internal.Clock = clock

	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()

	sut := NewRepository(client)

	now := time.Now()
	past := now.Add(-5 * time.Second)
	future := now.Add(10 * time.Minute)

	// use producer function to convert channel correctly
	// else we see error: panic: interface conversion: interface {} is chan time.Time, not <-chan time.Time
	clock.
		On("Tick", mock.Anything).Return(func(_ time.Duration) <-chan time.Time { return ticker }).
		On("Now").Return(now)

	_ = sut.Store(ctx, internal.Secret{PublicID: "id-1", ExpiresAt: past})
	_ = sut.Store(ctx, internal.Secret{PublicID: "id-2", ExpiresAt: future})
	_ = sut.Store(ctx, internal.Secret{PublicID: "id-3", ExpiresAt: future, BurnAfterRead: true, AlreadyRead: false})
	_ = sut.Store(ctx, internal.Secret{PublicID: "id-4", ExpiresAt: future, BurnAfterRead: true, AlreadyRead: true})
	_ = sut.Store(ctx, internal.Secret{PublicID: "id-5", ExpiresAt: past, BurnAfterRead: true, AlreadyRead: false})

	go sut.StartCleanupJob(time.Hour)
	ticker <- now

	time.Sleep(200 * time.Millisecond)

	secrets, err := client.Secret.Query().All(ctx)
	assert.NoError(t, err)
	assert.Len(t, secrets, 2)
}
