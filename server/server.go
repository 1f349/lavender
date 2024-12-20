package server

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"github.com/1f349/cache"
	clientStore "github.com/1f349/lavender/client-store"
	"github.com/1f349/lavender/conf"
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/issuer"
	"github.com/1f349/lavender/logger"
	"github.com/1f349/lavender/openid"
	"github.com/1f349/lavender/pages"
	scope2 "github.com/1f349/lavender/scope"
	"github.com/1f349/mjwt"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

var errInvalidScope = errors.New("missing required scope")

type HttpServer struct {
	r          *httprouter.Router
	oauthSrv   *server.Server
	oauthMgr   *manage.Manager
	db         *database.Queries
	conf       conf.Conf
	signingKey *mjwt.Issuer
	manager    *issuer.Manager
	flowState  *cache.Cache[string, flowStateData]
}

type flowStateData struct {
	loginName string
	sso       *issuer.WellKnownOIDC
	redirect  string
}

func NewHttpServer(config conf.Conf, db *database.Queries, signingKey *mjwt.Issuer) *httprouter.Router {
	r := httprouter.New()
	contentCache := time.Now()

	// remove last slash from baseUrl
	{
		l := len(config.BaseUrl)
		if config.BaseUrl[l-1] == '/' {
			config.BaseUrl = config.BaseUrl[:l-1]
		}
	}

	openIdConf := openid.GenConfig(config.BaseUrl, []string{"openid", "name", "username", "profile", "email", "birthdate", "age", "zoneinfo", "locale"}, []string{"sub", "name", "preferred_username", "profile", "picture", "website", "email", "email_verified", "gender", "birthdate", "zoneinfo", "locale", "updated_at"})
	openIdBytes, err := json.Marshal(openIdConf)
	if err != nil {
		logger.Logger.Fatal("Failed to generate OpenID configuration", "err", err)
	}

	jwkSetBuffer := new(bytes.Buffer)
	err = mjwt.WriteJwkSetJson(jwkSetBuffer, []*mjwt.Issuer{signingKey})
	if err != nil {
		logger.Logger.Fatal("Failed to generate JWK Set", "err", err)
	}

	oauthManager := manage.NewDefaultManager()
	oauthSrv := server.NewServer(server.NewConfig(), oauthManager)
	hs := &HttpServer{
		r:          httprouter.New(),
		oauthSrv:   oauthSrv,
		oauthMgr:   oauthManager,
		db:         db,
		conf:       config,
		signingKey: signingKey,
		flowState:  cache.New[string, flowStateData](),
	}

	hs.manager, err = issuer.NewManager(config.SsoServices)
	if err != nil {
		logger.Logger.Fatal("Failed to reload SSO service manager", "err", err)
	}

	oauthManager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	oauthManager.MustTokenStorage(store.NewMemoryTokenStore())
	oauthManager.MapAccessGenerate(NewJWTAccessGenerate(hs.signingKey, db))
	oauthManager.MapClientStorage(clientStore.New(db))

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
	oauthSrv.SetAuthorizeScopeHandler(func(rw http.ResponseWriter, req *http.Request) (scope string, err error) {
		var form url.Values
		if req.Method == http.MethodPost {
			form = req.PostForm
		} else {
			form = req.URL.Query()
		}
		a := form.Get("scope")
		if !scope2.ScopesExist(a) {
			return "", errInvalidScope
		}
		return a, nil
	})
	addIdTokenSupport(oauthSrv, db, signingKey)

	r.GET("/.well-known/openid-configuration", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write(openIdBytes)
	})
	r.GET("/.well-known/jwks.json", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write(jwkSetBuffer.Bytes())
	})
	r.GET("/", hs.OptionalAuthentication(hs.Home))

	// login
	r.GET("/login", hs.OptionalAuthentication(hs.loginGet))
	r.POST("/login", hs.OptionalAuthentication(hs.loginPost))
	r.GET("/callback", hs.OptionalAuthentication(hs.loginCallback))
	r.POST("/logout", hs.RequireAuthentication(func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, auth UserAuth) {
		cookie, err := req.Cookie("lavender-nonce")
		if err != nil {
			http.Error(rw, "Missing nonce", http.StatusBadRequest)
			return
		}
		if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(req.PostFormValue("nonce"))) == 1 {
			http.SetCookie(rw, &http.Cookie{
				Name:     "lavender-login-access",
				Path:     "/",
				MaxAge:   -1,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
			})
			http.SetCookie(rw, &http.Cookie{
				Name:     "lavender-login-refresh",
				Path:     "/",
				MaxAge:   -1,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
			})

			http.Redirect(rw, req, "/", http.StatusFound)
			return
		}
		http.Error(rw, "Logout failed", http.StatusInternalServerError)
	}))

	// theme styles
	r.GET("/assets/*filepath", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		name := params.ByName("filepath")
		if strings.Contains(name, "..") {
			http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		out := pages.RenderCss(path.Join("assets", name))
		http.ServeContent(rw, req, path.Base(name), contentCache, out)
	})

	// management pages
	r.GET("/manage/apps", hs.RequireAuthentication(hs.ManageAppsGet))
	r.GET("/manage/apps/create", hs.RequireAuthentication(hs.ManageAppsCreateGet))
	r.POST("/manage/apps", hs.RequireAuthentication(hs.ManageAppsPost))
	r.GET("/manage/users", hs.RequireAdminAuthentication(hs.ManageUsersGet))
	r.POST("/manage/users", hs.RequireAdminAuthentication(hs.ManageUsersPost))

	// oauth pages
	r.GET("/authorize", hs.RequireAuthentication(hs.authorizeEndpoint))
	r.POST("/authorize", hs.RequireAuthentication(hs.authorizeEndpoint))
	r.POST("/token", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		if err := oauthSrv.HandleTokenRequest(rw, req); err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
		}
	})
	userInfoRequest := func(rw http.ResponseWriter, req *http.Request, _ httprouter.Params) {
		rw.Header().Set("Access-Control-Allow-Credentials", "true")
		rw.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type")
		rw.Header().Set("Access-Control-Allow-Origin", strings.TrimSuffix(req.Referer(), "/"))
		rw.Header().Set("Access-Control-Allow-Methods", "GET")
		if req.Method == http.MethodOptions {
			return
		}

		token, err := oauthSrv.ValidationBearerToken(req)
		if err != nil {
			http.Error(rw, "403 Forbidden", http.StatusForbidden)
			return
		}
		userId := token.GetUserID()

		sso := hs.manager.FindServiceFromLogin(userId)
		if sso == nil {
			http.Error(rw, "Invalid user", http.StatusBadRequest)
			return
		}

		var user database.User
		if hs.DbTx(rw, func(tx *database.Queries) (err error) {
			user, err = tx.GetUser(req.Context(), userId)
			return
		}) {
			return
		}

		var userInfo UserInfoFields
		err = json.Unmarshal([]byte(user.Userinfo), &userInfo)
		if err != nil {
			http.Error(rw, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		claims := ParseClaims(token.GetScope())
		if !claims["openid"] {
			http.Error(rw, "Invalid scope", http.StatusBadRequest)
			return
		}

		m := make(map[string]any)

		if claims["name"] {
			m["name"] = userInfo["name"]
		}
		if claims["username"] {
			m["preferred_username"] = userInfo["preferred_username"]
			m["login"] = userInfo["login"]
		}
		if claims["profile"] {
			m["profile"] = userInfo["profile"]
			m["picture"] = userInfo["picture"]
			m["website"] = userInfo["website"]
		}
		if claims["email"] {
			m["email"] = userInfo["email"]
			m["email_verified"] = userInfo["email_verified"]
		}
		if claims["birthdate"] {
			m["birthdate"] = userInfo["birthdate"]
		}
		if claims["age"] {
			m["age"] = userInfo["age"]
		}
		if claims["zoneinfo"] {
			m["zoneinfo"] = userInfo["zoneinfo"]
		}
		if claims["locale"] {
			m["locale"] = userInfo["locale"]
		}

		m["sub"] = userId
		m["aud"] = token.GetClientID()
		m["updated_at"] = time.Now().Unix()

		_ = json.NewEncoder(rw).Encode(m)
	}
	r.GET("/userinfo", userInfoRequest)
	r.OPTIONS("/userinfo", userInfoRequest)

	return r
}

func (h *HttpServer) SafeRedirect(rw http.ResponseWriter, req *http.Request) {
	redirectUrl := req.FormValue("redirect")
	if redirectUrl == "" {
		http.Redirect(rw, req, "/", http.StatusFound)
		return
	}
	parse, err := url.Parse(redirectUrl)
	if err != nil {
		http.Error(rw, "Failed to parse redirect url: "+redirectUrl, http.StatusBadRequest)
		return
	}
	if parse.Scheme != "" && parse.Opaque != "" && parse.User != nil && parse.Host != "" {
		http.Error(rw, "Invalid redirect url: "+redirectUrl, http.StatusBadRequest)
		return
	}
	http.Redirect(rw, req, parse.String(), http.StatusFound)
}

func ParseClaims(claims string) map[string]bool {
	m := make(map[string]bool)
	for {
		n := strings.IndexByte(claims, ' ')
		if n == -1 {
			if claims != "" {
				m[claims] = true
			}
			break
		}

		a := claims[:n]
		claims = claims[n+1:]
		if a != "" {
			m[a] = true
		}
	}

	return m
}
