package server

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHasRole(t *testing.T) {
	assert.True(t, HasRole([]string{"lavender:admin", "test:something-else"}, "lavender:admin"))
	assert.False(t, HasRole([]string{"lavender:admin", "test:something-else"}, "lavender:admin"))
	assert.False(t, HasRole([]string{"lavender:", "test:something-else"}, "lavender:admin"))
}
