package issuer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/utils"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

type WellKnownOIDC struct {
	Namespace              string               `json:"-"`
	Config                 database.OauthSource `json:"-"`
	Available              atomic.Bool          `json:"-"`
	Issuer                 string               `json:"issuer"`
	AuthorizationEndpoint  *utils.URL           `json:"authorization_endpoint"`
	TokenEndpoint          *utils.URL           `json:"token_endpoint"`
	UserInfoEndpoint       *utils.URL           `json:"userinfo_endpoint"`
	ResponseTypesSupported []string             `json:"response_types_supported"`
	ScopesSupported        []string             `json:"scopes_supported"`
	ClaimsSupported        []string             `json:"claims_supported"`
	GrantTypesSupported    []string             `json:"grant_types_supported"`
	JwksUri                *utils.URL           `json:"jwks_uri"`
	OAuth2Config           oauth2.Config        `json:"-"`
	LastFetch              time.Time            `json:"-"`
}

func fetchConfig(ctx context.Context, httpClient *http.Client, s database.OauthSource) (*WellKnownOIDC, error) {
	// generate openid config url
	u := s.Address.JoinPath(".well-known/openid-configuration")

	// fetch metadata
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var c WellKnownOIDC
	err = json.NewDecoder(resp.Body).Decode(&c)
	if err != nil {
		return nil, err
	}
	c.Config = s
	c.OAuth2Config = oauth2.Config{
		ClientID:     c.Config.ClientID,
		ClientSecret: c.Config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   c.AuthorizationEndpoint.String(),
			TokenURL:  c.TokenEndpoint.String(),
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		Scopes: strings.Fields(c.Config.ClientScopes),
	}
	c.Available.Store(true)
	return &c, nil
}

func (o *WellKnownOIDC) Validate() error {
	if o.Issuer == "" {
		return errors.New("missing issuer")
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

func (o *WellKnownOIDC) ValidReturnUrl(u *url.URL) bool {
	return o.Config.Address.Scheme == u.Scheme && o.Config.Address.Host == u.Host
}
