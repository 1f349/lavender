package server

import (
	"encoding/json"
	"fmt"
	auth2 "github.com/1f349/lavender/auth"
	clientStore "github.com/1f349/lavender/client-store"
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/logger"
	"github.com/1f349/lavender/pages"
	"github.com/1f349/lavender/scope"
	"github.com/1f349/lavender/utils"
	"github.com/1f349/mjwt"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"
)

func SetupOAuth2(r *httprouter.Router, hs *httpServer, key *mjwt.Issuer, db *database.Queries) {
	oauthManager := manage.NewDefaultManager()
	oauthManager.MapAuthorizeGenerate(generates.NewAuthorizeGenerate())
	oauthManager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	oauthManager.MustTokenStorage(store.NewMemoryTokenStore())
	oauthManager.MapAccessGenerate(NewMJWTAccessGenerate(key, db))
	oauthManager.MapClientStorage(clientStore.New(db))

	oauthSrv := server.NewDefaultServer(oauthManager)
	oauthSrv.SetClientInfoHandler(func(req *http.Request) (clientID, clientSecret string, err error) {
		cId, cSecret, err := server.ClientBasicHandler(req)
		if cId == "" && cSecret == "" {
			cId, cSecret, err = server.ClientFormHandler(req)
		}
		if err != nil {
			return "", "", err
		}
		return cId, cSecret, nil
	})
	oauthSrv.SetUserAuthorizationHandler(hs.oauthUserAuthorization)
	oauthSrv.SetAuthorizeScopeHandler(func(rw http.ResponseWriter, req *http.Request) (string, error) {
		var form url.Values
		if req.Method == http.MethodPost {
			form = req.PostForm
		} else {
			form = req.URL.Query()
		}
		a := form.Get("scope")
		if !scope.ScopesExist(a) {
			return "", errInvalidScope
		}
		return a, nil
	})
	oauthSrv.ClientAuthorizedHandler = func(clientID string, grant oauth2.GrantType) (allowed bool, err error) {
		return true, nil
	}
	addIdTokenSupport(oauthSrv, db, key)
	oauthSrv.ResponseErrorHandler = func(re *errors.Response) {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, false)
		fmt.Printf("%#v\n", re)
		fmt.Printf("%s\n", buf[:n])
	}

	hs.oauthMgr = oauthManager
	hs.oauthSrv = oauthSrv

	r.GET("/authorize", hs.RequireAuthentication(hs.authorizeEndpoint))
	r.POST("/authorize", hs.RequireAuthentication(hs.authorizeEndpoint))
	r.POST("/token", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		if err := oauthSrv.HandleTokenRequest(rw, req); err != nil {
			http.Error(rw, "Failed to handle token request", http.StatusInternalServerError)
		}
	})
	r.GET("/userinfo", hs.userInfoRequest)
	r.OPTIONS("/userinfo", hs.userInfoRequest)
}

func (h *httpServer) userInfoRequest(rw http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	rw.Header().Set("Access-Control-Allow-Credentials", "true")
	rw.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type")
	rw.Header().Set("Access-Control-Allow-Origin", strings.TrimSuffix(req.Referer(), "/"))
	rw.Header().Set("Access-Control-Allow-Methods", "GET")
	if req.Method == http.MethodOptions {
		return
	}

	token, err := h.oauthSrv.ValidationBearerToken(req)
	if err != nil {
		http.Error(rw, "403 Forbidden", http.StatusForbidden)
		return
	}
	userId := token.GetUserID()

	var user database.User
	if h.DbTx(rw, func(tx *database.Queries) (err error) {
		user, err = tx.GetUser(req.Context(), userId)
		return
	}) {
		return
	}

	claims := ParseClaims(token.GetScope())
	if !claims["openid"] {
		http.Error(rw, "Invalid scope", http.StatusBadRequest)
		return
	}

	m := make(map[string]any)

	if claims["name"] {
		m["name"] = user.Name
	}
	if claims["username"] {
		m["preferred_username"] = user.Login
		m["login"] = user.Login
	}
	if claims["profile"] {
		m["profile"] = user.ProfileUrl
		m["picture"] = user.Picture
		m["website"] = user.Website
	}
	if claims["email"] {
		m["email"] = user.Email
		m["email_verified"] = user.EmailVerified
	}
	if claims["birthdate"] && user.Birthdate.Valid {
		m["birthdate"] = user.Birthdate.Date
	}
	if claims["age"] && user.Birthdate.Valid {
		m["age"] = utils.Age(user.Birthdate.Date.ToTime())
	}
	if claims["zoneinfo"] {
		m["zoneinfo"] = user.Zone
	}
	if claims["locale"] {
		m["locale"] = user.Locale
	}

	m["sub"] = userId
	m["aud"] = token.GetClientID()
	m["updated_at"] = time.Now().Unix()

	_ = json.NewEncoder(rw).Encode(m)
}

func (h *httpServer) authorizeEndpoint(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth auth2.UserAuth) {
	// function is only called with GET or POST method
	isPost := req.Method == http.MethodPost

	var form url.Values
	if isPost {
		err := req.ParseForm()
		if err != nil {
			http.Error(rw, "Failed to parse form", http.StatusInternalServerError)
			return
		}
		form = req.PostForm
	} else {
		form = req.URL.Query()
	}

	clientID := form.Get("client_id")
	client, err := h.oauthMgr.GetClient(req.Context(), clientID)
	if err != nil {
		http.Error(rw, "Invalid client", http.StatusBadRequest)
		return
	}

	redirectUri := form.Get("redirect_uri")
	clientDomains := strings.Fields(client.GetDomain())
	allowedDomains := make(map[string]bool)
	for _, i := range clientDomains {
		allowedDomains[i] = true
	}

	if !allowedDomains[redirectUri] {
		http.Error(rw, "Incorrect redirect URI", http.StatusBadRequest)
		return
	}

	if form.Has("cancel") {
		uCancel, err := url.Parse(redirectUri)
		if err != nil {
			http.Error(rw, "Invalid redirect URI", http.StatusBadRequest)
			return
		}
		q := uCancel.Query()
		q.Set("error", "access_denied")
		uCancel.RawQuery = q.Encode()

		http.Redirect(rw, req, uCancel.String(), http.StatusFound)
		return
	}

	var isSSO bool
	if clientIsSSO, ok := client.(interface{ IsSSO() bool }); ok {
		isSSO = clientIsSSO.IsSSO()
	}

	switch {
	case isSSO && isPost:
		http.Error(rw, "400 Bad Request: Not sure how you even managed to send a POST request for an SSO application", http.StatusBadRequest)
		return
	case !isSSO && !isPost:
		// find application redirect domain and name
		appUrlFull, err := url.Parse(redirectUri)
		if err != nil {
			http.Error(rw, "500 Internal Server Error: Failed to parse application redirect URL", http.StatusInternalServerError)
			return
		}
		appDomain := appUrlFull.Scheme + "://" + appUrlFull.Host
		appName := appUrlFull.Host
		if clientGetName, ok := client.(interface{ GetName() string }); ok {
			n := clientGetName.GetName()
			if n != "" {
				appName = n
			}
		}

		scopeList := form.Get("scope")
		if !scope.ScopesExist(scopeList) {
			http.Error(rw, "Invalid scopes", http.StatusBadRequest)
			return
		}

		rw.WriteHeader(http.StatusOK)
		pages.RenderPageTemplate(rw, "oauth-authorize", map[string]any{
			"ServiceName":  h.conf.ServiceName,
			"AppName":      appName,
			"AppDomain":    appDomain,
			"DisplayName":  auth.UserInfo.GetStringOrEmpty("name"),
			"WantsList":    scope.FancyScopeList(scopeList),
			"ResponseType": form.Get("response_type"),
			"ResponseMode": form.Get("response_mode"),
			"ClientID":     form.Get("client_id"),
			"RedirectUri":  form.Get("redirect_uri"),
			"State":        form.Get("state"),
			"Scope":        scopeList,
			"Nonce":        form.Get("nonce"),
		})
		return
	}

	// redirect with an error if the action is not authorize
	if form.Get("oauth_action") == "authorize" || isSSO {
		if err := h.oauthSrv.HandleAuthorizeRequest(rw, req); err != nil {
			logger.Logger.Error(err)
			http.Error(rw, err.Error(), http.StatusBadRequest)
		}
		return
	}

	parsedRedirect, err := url.Parse(redirectUri)
	if err != nil {
		http.Error(rw, "400 Bad Request: Invalid redirect URI", http.StatusBadRequest)
		return
	}
	q := parsedRedirect.Query()
	q.Set("error", "user_cancelled")
	parsedRedirect.RawQuery = q.Encode()
	http.Redirect(rw, req, parsedRedirect.String(), http.StatusFound)
}

func (h *httpServer) oauthUserAuthorization(rw http.ResponseWriter, req *http.Request) (string, error) {
	err := req.ParseForm()
	if err != nil {
		return "", err
	}

	auth, err := h.internalAuthenticationHandler(rw, req)
	if err != nil {
		return "", err
	}

	if auth.IsGuest() {
		// handle redirecting to oauth
		var q url.Values
		switch req.Method {
		case http.MethodPost:
			q = req.PostForm
		case http.MethodGet:
			q = req.URL.Query()
		default:
			http.Error(rw, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return "", err
		}

		redirectUrl := auth2.PrepareRedirectUrl("/login", &url.URL{Path: "/authorize", RawQuery: q.Encode()})
		http.Redirect(rw, req, redirectUrl.String(), http.StatusFound)
		return "", nil
	}
	return auth.Subject, nil
}
