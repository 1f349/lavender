package server

import (
	"context"
	"github.com/1f349/lavender/auth"
	"github.com/1f349/mjwt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestUserAuth_NextFlowUrl(t *testing.T) {
	u := auth.UserAuth{Factor: 0}
	assert.Equal(t, url.URL{Path: "/login"}, *u.NextFlowUrl(&url.URL{}))
	assert.Equal(t, url.URL{Path: "/login", RawQuery: url.Values{"redirect": {"/hello"}}.Encode()}, *u.NextFlowUrl(&url.URL{Path: "/hello"}))
	assert.Equal(t, url.URL{Path: "/login", RawQuery: url.Values{"redirect": {"/hello?a=A"}}.Encode()}, *u.NextFlowUrl(&url.URL{Path: "/hello", RawQuery: url.Values{"a": {"A"}}.Encode()}))
	u.Factor = auth.FactorAuthorized
	assert.Nil(t, u.NextFlowUrl(&url.URL{}))
}

func TestUserAuth_IsGuest(t *testing.T) {
	var u auth.UserAuth
	assert.True(t, u.IsGuest())
	u.Subject = uuid.NewString()
	assert.False(t, u.IsGuest())
}

type fakeSessionStore struct {
	m        map[string]any
	saveFunc func(map[string]any) error
}

func (f *fakeSessionStore) Context() context.Context          { return context.Background() }
func (f *fakeSessionStore) SessionID() string                 { return "fakeSessionStore" }
func (f *fakeSessionStore) Set(key string, value interface{}) { f.m[key] = value }

func (f *fakeSessionStore) Get(key string) (a interface{}, ok bool) {
	if a, ok = f.m[key]; false {
	}
	return
}

func TestRequireAuthentication(t *testing.T) {
}

func TestOptionalAuthentication(t *testing.T) {
	jwtIssuer, err := mjwt.NewIssuer("TestIssuer", uuid.NewString(), jwt.SigningMethodRS512)
	h := &httpServer{signingKey: jwtIssuer}
	rec := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "https://example.com/hello", nil)
	assert.NoError(t, err)
	authData, err := h.internalAuthenticationHandler(rec, req)
	assert.NoError(t, err)
	assert.True(t, authData.IsGuest())
	authData.Subject = "567"
}

func TestPrepareRedirectUrl(t *testing.T) {
	assert.Equal(t, url.URL{Path: "/hello"}, *auth.PrepareRedirectUrl("/hello", &url.URL{}))
	assert.Equal(t, url.URL{Path: "/world"}, *auth.PrepareRedirectUrl("/world", &url.URL{}))
	assert.Equal(t, url.URL{Path: "/a", RawQuery: url.Values{"redirect": {"/hello"}}.Encode()}, *auth.PrepareRedirectUrl("/a", &url.URL{Path: "/hello"}))
	assert.Equal(t, url.URL{Path: "/a", RawQuery: url.Values{"redirect": {"/hello?a=A"}}.Encode()}, *auth.PrepareRedirectUrl("/a", &url.URL{Path: "/hello", RawQuery: url.Values{"a": {"A"}}.Encode()}))
	assert.Equal(t, url.URL{Path: "/a", RawQuery: url.Values{"redirect": {"/hello?a=A&b=B"}}.Encode()}, *auth.PrepareRedirectUrl("/a", &url.URL{Path: "/hello", RawQuery: url.Values{"a": {"A"}, "b": {"B"}}.Encode()}))

	assert.Equal(t, url.URL{Path: "/hello", RawQuery: "z=y"}, *auth.PrepareRedirectUrl("/hello?z=y", &url.URL{}))
	assert.Equal(t, url.URL{Path: "/world", RawQuery: "z=y"}, *auth.PrepareRedirectUrl("/world?z=y", &url.URL{}))
	assert.Equal(t, url.URL{Path: "/a", RawQuery: url.Values{"z": {"y"}, "redirect": {"/hello"}}.Encode()}, *auth.PrepareRedirectUrl("/a?z=y", &url.URL{Path: "/hello"}))
	assert.Equal(t, url.URL{Path: "/a", RawQuery: url.Values{"z": {"y"}, "redirect": {"/hello?a=A"}}.Encode()}, *auth.PrepareRedirectUrl("/a?z=y", &url.URL{Path: "/hello", RawQuery: url.Values{"a": {"A"}}.Encode()}))
	assert.Equal(t, url.URL{Path: "/a", RawQuery: url.Values{"z": {"y"}, "redirect": {"/hello?a=A&b=B"}}.Encode()}, *auth.PrepareRedirectUrl("/a?z=y", &url.URL{Path: "/hello", RawQuery: url.Values{"a": {"A"}, "b": {"B"}}.Encode()}))
}
