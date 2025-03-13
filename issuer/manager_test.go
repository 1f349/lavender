package issuer

import (
	"context"
	"fmt"
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/utils"
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

var testAddrUrl = func() utils.URL {
	a, err := url.Parse("https://example.com")
	if err != nil {
		panic(err)
	}
	return utils.URL{URL: a}
}()

func testBody() io.ReadCloser {
	return io.NopCloser(strings.NewReader(`{
  "issuer": "Example.com Issuer",
  "authorization_endpoint": "https://example.com/oauth/authorize",
	"token_endpoint": "https://example.com/oauth/token",
	"userinfo_endpoint": "https://example.com/oauth/userinfo",
	"revocation_endpoint": "https://example.com/oauth/revoke",
	"response_types_supported": [
		"code"
	],
	"scopes_supported": [
		"openid"
	],
	"claims_supported": [
		"sub"
	],
	"grant_types_supported": [
    "authorization_code",
    "refresh_token"
  ]
}
`))
}

func TestManager_CheckNamespace(t *testing.T) {
	manager, err := NewManagerWithClient(&testDB{
		Rows: []database.OauthSource{
			{Address: testAddrUrl, Namespace: "example.com"},
		},
	}, "example.org", &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			fmt.Println("Request URL:", req.URL)
			if req.URL.String() == "https://example.com/.well-known/openid-configuration" {
				return &http.Response{StatusCode: http.StatusOK, Body: testBody()}, nil
			}
			return nil, fmt.Errorf("request failed")
		}),
	})
	assert.NoError(t, err)
	assert.True(t, manager.CheckNamespace("example.org"))
	assert.True(t, manager.CheckNamespace("example.com"))
	assert.False(t, manager.CheckNamespace("missing.example.com"))
}

func TestManager_FindServiceFromLogin(t *testing.T) {
	manager, err := NewManagerWithClient(&testDB{
		Rows: []database.OauthSource{
			{Address: testAddrUrl, Namespace: "example.com"},
		},
	}, "example.org", &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			fmt.Println("Request URL:", req.URL)
			if req.URL.String() != "https://example.com/.well-known/openid-configuration" {
				return &http.Response{StatusCode: http.StatusOK, Body: testBody()}, nil
			}
			return nil, fmt.Errorf("request failed")
		}),
	})
	assert.NoError(t, err)
	assert.Equal(t, manager.GetService("example.org"), MeWellKnown)
	assert.Equal(t, manager.GetService("example.com"), manager.sourceMap["example.com"])
	assert.Nil(t, manager.GetService("missing.example.com"))
}

type testDB struct {
	Rows []database.OauthSource
}

func (t *testDB) GetOAuthSources(ctx context.Context) ([]database.OauthSource, error) {
	return t.Rows, nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (r roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	time.Sleep(time.Minute)
	return r(req)
}
