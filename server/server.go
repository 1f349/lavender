package server

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"github.com/1f349/cache"
	clientStore "github.com/1f349/lavender/client-store"
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/issuer"
	"github.com/1f349/lavender/openid"
	scope2 "github.com/1f349/lavender/scope"
	"github.com/1f349/lavender/theme"
	"github.com/1f349/mjwt"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/go-session/session"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var errInvalidScope = errors.New("missing required scope")

type HttpServer struct {
	r          *httprouter.Router
	oauthSrv   *server.Server
	oauthMgr   *manage.Manager
	db         *database.DB
	conf       Conf
	signingKey mjwt.Signer
	manager    *issuer.Manager
	flowState  *cache.Cache[string, flowStateData]
}

type flowStateData struct {
	sso      *issuer.WellKnownOIDC
	redirect string
}

func NewHttpServer(conf Conf, db *database.DB, signingKey mjwt.Signer) *http.Server {
	session.InitManager(session.SetCookieName("lavender_session"))

	r := httprouter.New()

	// remove last slash from baseUrl
	{
		l := len(conf.BaseUrl)
		if conf.BaseUrl[l-1] == '/' {
			conf.BaseUrl = conf.BaseUrl[:l-1]
		}
	}

	openIdConf := openid.GenConfig(conf.BaseUrl, []string{"openid", "name", "username", "profile", "email", "birthdate", "age", "zoneinfo", "locale"}, []string{"sub", "name", "preferred_username", "profile", "picture", "website", "email", "email_verified", "gender", "birthdate", "zoneinfo", "locale", "updated_at"})
	openIdBytes, err := json.Marshal(openIdConf)
	if err != nil {
		log.Fatalln("Failed to generate OpenID configuration:", err)
	}

	oauthManager := manage.NewDefaultManager()
	oauthSrv := server.NewServer(server.NewConfig(), oauthManager)
	hs := &HttpServer{
		r:          httprouter.New(),
		oauthSrv:   oauthSrv,
		oauthMgr:   oauthManager,
		db:         db,
		conf:       conf,
		signingKey: signingKey,
		flowState:  cache.New[string, flowStateData](),
	}

	hs.manager, err = issuer.NewManager(conf.SsoServices)
	if err != nil {
		log.Fatal("Failed to reload SSO service manager: %w", err)
	}

	oauthManager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	oauthManager.MustTokenStorage(store.NewMemoryTokenStore())
	oauthManager.MapAccessGenerate(NewJWTAccessGenerate(hs.signingKey, db))
	oauthManager.MapClientStorage(clientStore.New(db))

	oauthSrv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Printf("Response error: %#v\n", re)
	})
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
	r.GET("/", hs.OptionalAuthentication(hs.Home))

	// login
	r.GET("/login", hs.OptionalAuthentication(hs.loginGet))
	r.POST("/login", hs.OptionalAuthentication(hs.loginPost))
	r.GET("/callback", hs.OptionalAuthentication(hs.loginCallback))
	r.POST("/logout", hs.RequireAuthentication(func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, auth UserAuth) {
		lNonce, ok := auth.Session.Get("action-nonce")
		if !ok {
			http.Error(rw, "Missing nonce", http.StatusInternalServerError)
			return
		}
		if subtle.ConstantTimeCompare([]byte(lNonce.(string)), []byte(req.PostFormValue("nonce"))) == 1 {
			auth.Session.Delete("session-data")
			if auth.Session.Save() != nil {
				http.Error(rw, "Failed to save session", http.StatusInternalServerError)
				return
			}

			http.SetCookie(rw, &http.Cookie{
				Name:     "lavender-login-data",
				Path:     "/",
				MaxAge:   -1,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
			})

			http.Redirect(rw, req, "/", http.StatusFound)
			return
		}
		http.Error(rw, "Logout failed", http.StatusInternalServerError)
	}))

	// theme styles
	r.GET("/theme/style.css", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		http.ServeContent(rw, req, "style.css", time.Now(), bytes.NewReader(theme.DefaultThemeCss))
	})

	// management pages
	r.GET("/manage/apps", hs.RequireAuthentication(hs.ManageAppsGet))
	r.POST("/manage/apps", hs.RequireAuthentication(hs.ManageAppsPost))
	r.GET("/manage/users", hs.RequireAdminAuthentication(hs.ManageUsersGet))
	r.POST("/manage/users", hs.RequireAdminAuthentication(hs.ManageUsersPost))

	// oauth pages
	r.GET("/authorize", hs.RequireAuthentication(hs.authorizeEndpoint))
	r.POST("/authorize", hs.RequireAuthentication(hs.authorizeEndpoint))
	r.POST("/token", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		// TODO: id_token support
		// https://code.mrmelon54.com/melon/summer/src/commit/7b8afa8b91c39eba749f60a45965fd8f75c87147/pkg/oauth-server/server.go#L216
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

		log.Println(userId)
		sso := hs.manager.FindServiceFromLogin(userId)
		if sso == nil {
			http.Error(rw, "Invalid user", http.StatusBadRequest)
			return
		}

		var clientToken oauth2.Token
		if hs.DbTx(rw, func(tx *database.Tx) error {
			return tx.GetUserToken(userId, &clientToken.AccessToken, &clientToken.RefreshToken, &clientToken.Expiry)
		}) {
			return
		}

		info, err := hs.fetchUserInfo(sso, &clientToken)
		if err != nil {
			http.Error(rw, "Failed to fetch user info", http.StatusInternalServerError)
			return
		}

		fmt.Printf("Using token for user: %s by app: %s with scope: '%s'\n", userId, token.GetClientID(), token.GetScope())
		claims := ParseClaims(token.GetScope())
		if !claims["openid"] {
			http.Error(rw, "Invalid scope", http.StatusBadRequest)
			return
		}

		m := make(map[string]any)

		if claims["name"] {
			m["name"] = info.UserInfo["name"]
		}
		if claims["username"] {
			m["preferred_username"] = info.UserInfo["preferred_username"]
			m["login"] = info.UserInfo["login"]
		}
		if claims["profile"] {
			m["profile"] = info.UserInfo["profile"]
			m["picture"] = info.UserInfo["picture"]
			m["website"] = info.UserInfo["website"]
		}
		if claims["email"] {
			m["email"] = info.UserInfo["email"]
			m["email_verified"] = info.UserInfo["email_verified"]
		}
		if claims["birthdate"] {
			m["birthdate"] = info.UserInfo["birthdate"]
		}
		if claims["age"] {
			m["age"] = info.UserInfo["age"]
		}
		if claims["zoneinfo"] {
			m["zoneinfo"] = info.UserInfo["zoneinfo"]
		}
		if claims["locale"] {
			m["locale"] = info.UserInfo["locale"]
		}

		m["sub"] = userId
		m["aud"] = token.GetClientID()
		m["updated_at"] = time.Now().Unix()

		_ = json.NewEncoder(rw).Encode(m)
	}
	r.GET("/userinfo", userInfoRequest)
	r.OPTIONS("/userinfo", userInfoRequest)

	return &http.Server{
		Addr:              conf.Listen,
		Handler:           r,
		ReadTimeout:       time.Minute,
		ReadHeaderTimeout: time.Minute,
		WriteTimeout:      time.Minute,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    2500,
	}
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
