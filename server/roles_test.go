package server

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHasRole(t *testing.T) {
	assert.True(t, HasRole("lavender:admin test:something-else", "lavender:admin"))
	assert.False(t, HasRole("lavender:admin,test:something-else", "lavender:admin"))
	assert.False(t, HasRole("lavender: test:something-else", "lavender:admin"))
}
