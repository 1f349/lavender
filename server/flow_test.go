package server

import (
	"fmt"
	"github.com/1f349/cache"
	"github.com/1f349/lavender/issuer"
	"github.com/1f349/lavender/server/pages"
	"github.com/1f349/lavender/utils"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const lavenderDomain = "http://localhost:0"
const clientAppDomain = "http://localhost:1"
const loginDomain = "http://localhost:2"

func init() {
	err := pages.LoadPages("")
	if err != nil {
		panic(err)
	}
}

func TestFlowPopup(t *testing.T) {
	h := HttpServer{conf: Conf{ServiceName: "Test Service Name"}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/popup?"+url.Values{"origin": []string{clientAppDomain}}.Encode(), nil)
	h.flowPopup(rec, req, httprouter.Params{})
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <title>Test Service Name</title>
</head>
<body>
<header>
    <h1>Test Service Name</h1>
</header>
<main>
    <form method="POST" action="/popup">
        <input type="hidden" name="origin" value="%s"/>
        <div>
            <label for="field_loginname">Login Name:</label>
            <input type="text" name="loginname" id="field_loginname" required/>
        </div>
        <button type="submit">Continue</button>
    </form>
</main>
</body>
</html>
`, clientAppDomain), rec.Body.String())
}

func TestFlowPopupPost(t *testing.T) {
	manager := issuer.NewManagerForTests([]issuer.WellKnownOIDC{
		{
			Config: issuer.SsoConfig{
				Addr:      utils.JsonUrl{},
				Namespace: "example.com",
				Client: issuer.SsoConfigClient{
					ID:     "test-id",
					Secret: "test-secret",
					Scopes: []string{"openid"},
				},
			},
			Issuer:                 "https://example.com",
			AuthorizationEndpoint:  loginDomain + "/authorize",
			TokenEndpoint:          loginDomain + "/token",
			UserInfoEndpoint:       loginDomain + "/userinfo",
			ResponseTypesSupported: nil,
			ScopesSupported:        nil,
			ClaimsSupported:        nil,
			GrantTypesSupported:    nil,
			OAuth2Config: oauth2.Config{
				ClientID:     "test-id",
				ClientSecret: "test-secret",
				Endpoint: oauth2.Endpoint{
					AuthURL:   loginDomain + "/authorize",
					TokenURL:  loginDomain + "/token",
					AuthStyle: oauth2.AuthStyleInHeader,
				},
				Scopes: nil,
			},
		},
	})
	h := HttpServer{
		r:         nil,
		conf:      Conf{BaseUrl: lavenderDomain},
		manager:   manager,
		flowState: cache.New[string, flowStateData](),
		services: map[string]struct{}{
			clientAppDomain: {},
		},
	}

	// test no login service error
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/popup", strings.NewReader(url.Values{
		"loginname": []string{"test@missing.example.com"},
		"origin":    []string{clientAppDomain},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.flowPopupPost(rec, req, httprouter.Params{})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "No login service defined for this username\n", rec.Body.String())

	// test invalid target origin error
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/popup", strings.NewReader(url.Values{
		"loginname": []string{"test@example.com"},
		"origin":    []string{"http://localhost:1010"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.flowPopupPost(rec, req, httprouter.Params{})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "Invalid target origin\n", rec.Body.String())

	// test successful request
	nextState := uuid.NewString()
	uuidNewStringState = func() string { return nextState }
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/popup", strings.NewReader(url.Values{
		"loginname": []string{"test@example.com"},
		"origin":    []string{clientAppDomain},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.flowPopupPost(rec, req, httprouter.Params{})
	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, "", rec.Body.String())
	assert.Equal(t, loginDomain+"/authorize?"+url.Values{
		"client_id":     []string{"test-id"},
		"login_name":    []string{"test@example.com"},
		"redirect_uri":  []string{lavenderDomain + "/callback"},
		"response_type": []string{"code"},
		"state":         []string{"example.com:" + nextState},
	}.Encode(), rec.Header().Get("Location"))
}
