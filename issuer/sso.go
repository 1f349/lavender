package issuer

import (
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
	"path"
	"slices"
)

// SsoConfig is the base URL for an OAUTH/OPENID/SSO login service
// The path `/.well-known/openid-configuration` should be available
type SsoConfig struct {
	Addr      string `json:"addr"`      // https://login.example.com
	Namespace string `json:"namespace"` // example.com
	Client    struct {
		ID     string   `json:"id"`
		Secret string   `json:"secret"`
		Scopes []string `json:"scopes"`
	} `json:"client"`
}

func (s SsoConfig) FetchConfig() (*WellKnownOIDC, error) {
	confUrl := path.Join(s.Addr, ".well-known", "openid-configuration")
	get, err := http.Get(confUrl)
	if err != nil {
		return nil, err
	}
	defer get.Body.Close()

	var c WellKnownOIDC
	err = json.NewDecoder(get.Body).Decode(&c)
	return &c, err
}

type WellKnownOIDC struct {
	Config                 SsoConfig `json:"-"`
	Issuer                 string    `json:"issuer"`
	AuthorizationEndpoint  string    `json:"authorization_endpoint"`
	TokenEndpoint          string    `json:"token_endpoint"`
	UserInfoEndpoint       string    `json:"userinfo_endpoint"`
	ResponseTypesSupported []string  `json:"response_types_supported"`
	ScopesSupported        []string  `json:"scopes_supported"`
	ClaimsSupported        []string  `json:"claims_supported"`
	GrantTypesSupported    []string  `json:"grant_types_supported"`
}

func (o WellKnownOIDC) Validate() error {
	if o.Issuer == "" {
		return errors.New("missing issuer")
	}

	// check URLs are valid
	if _, err := url.Parse(o.AuthorizationEndpoint); err != nil {
		return err
	}
	if _, err := url.Parse(o.TokenEndpoint); err != nil {
		return err
	}
	if _, err := url.Parse(o.UserInfoEndpoint); err != nil {
		return err
	}

	// check oidc supported values
	if !slices.Contains(o.ResponseTypesSupported, "code") {
		return errors.New("missing required response type 'code'")
	}
	if !slices.Contains(o.ScopesSupported, "openid") {
		return errors.New("missing required scope 'openid'")
	}
	requiredClaims := []string{"sub", "name", "preferred_username", "email", "email_verified"}
	for _, i := range requiredClaims {
		if !slices.Contains(o.ClaimsSupported, i) {
			return fmt.Errorf("missing required claim '%s'", i)
		}
	}

	// oidc valid
	return nil
}

func (o WellKnownOIDC) Oauth2Config() oauth2.Config {
	return oauth2.Config{
		ClientID:     o.Config.Client.ID,
		ClientSecret: o.Config.Client.Secret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   o.AuthorizationEndpoint,
			TokenURL:  o.TokenEndpoint,
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		Scopes: o.Config.Client.Scopes,
	}
}
