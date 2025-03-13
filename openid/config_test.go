package openid

import (
	"github.com/1f349/lavender/utils"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGenConfig(t *testing.T) {
	assert.Equal(t, Config{
		Issuer:                 "https://example.com",
		AuthorizationEndpoint:  utils.MustParse("https://example.com/authorize"),
		TokenEndpoint:          utils.MustParse("https://example.com/token"),
		UserInfoEndpoint:       utils.MustParse("https://example.com/userinfo"),
		ResponseTypesSupported: []string{"code"},
		ScopesSupported:        []string{"openid", "email"},
		ClaimsSupported:        []string{"name", "email", "preferred_username"},
		GrantTypesSupported:    []string{"authorization_code", "refresh_token"},
		JwksUri:                utils.MustParse("https://example.com/.well-known/jwks.json"),
	}, GenConfig(utils.MustParse("https://example.com"), []string{"openid", "email"}, []string{"name", "email", "preferred_username"}))
}
