package openid

import "github.com/1f349/lavender/utils"

type Config struct {
	Issuer                 string     `json:"issuer"`
	AuthorizationEndpoint  *utils.URL `json:"authorization_endpoint"`
	TokenEndpoint          *utils.URL `json:"token_endpoint"`
	UserInfoEndpoint       *utils.URL `json:"userinfo_endpoint"`
	ResponseTypesSupported []string   `json:"response_types_supported"`
	ScopesSupported        []string   `json:"scopes_supported"`
	ClaimsSupported        []string   `json:"claims_supported"`
	GrantTypesSupported    []string   `json:"grant_types_supported"`
	JwksUri                *utils.URL `json:"jwks_uri"`
}

func GenConfig(baseUrl *utils.URL, scopes, claims []string) Config {
	return Config{
		Issuer:                 baseUrl.String(),
		AuthorizationEndpoint:  baseUrl.Resolve("authorize"),
		TokenEndpoint:          baseUrl.Resolve("token"),
		UserInfoEndpoint:       baseUrl.Resolve("userinfo"),
		ResponseTypesSupported: []string{"code"},
		ScopesSupported:        scopes,
		ClaimsSupported:        claims,
		GrantTypesSupported:    []string{"authorization_code", "refresh_token"},
		JwksUri:                baseUrl.Resolve(".well-known/jwks.json"),
	}
}
