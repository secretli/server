package config

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestGatherConfig(t *testing.T) {
	t.Run("forwarded prefix", func(t *testing.T) {
		t.Run("default works", func(t *testing.T) {
			config, err := GatherConfig()
			assert.NoError(t, err)
			assert.EqualValues(t, "/", config.ForwardedPrefix)
		})

		t.Run("setting value works", func(t *testing.T) {
			t.Setenv("FORWARDED_PREFIX", "/api/v2/")

			config, err := GatherConfig()
			assert.NoError(t, err)
			assert.EqualValues(t, "/api/v2/", config.ForwardedPrefix)
		})

		t.Run("attaches slash at the end", func(t *testing.T) {
			t.Setenv("FORWARDED_PREFIX", "/api/v3")

			config, err := GatherConfig()
			assert.NoError(t, err)
			assert.EqualValues(t, "/api/v3/", config.ForwardedPrefix)
		})

		t.Run("must start with a slash", func(t *testing.T) {
			t.Setenv("FORWARDED_PREFIX", "api/v4")

			_, err := GatherConfig()
			assert.Error(t, err)
		})
	})

	t.Run("cleanup interval", func(t *testing.T) {
		t.Run("default value", func(t *testing.T) {
			config, err := GatherConfig()
			assert.NoError(t, err)
			assert.EqualValues(t, time.Hour, config.CleanupInterval)
		})

		t.Run("setting value works", func(t *testing.T) {
			expected := 1*time.Hour + 35*time.Minute + 21*time.Second
			t.Setenv("CLEANUP_INTERVAL", "1h35m21s")

			config, err := GatherConfig()
			assert.NoError(t, err)
			assert.EqualValues(t, expected, config.CleanupInterval)
		})
	})
}
