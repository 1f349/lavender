package server

import (
	"errors"
	"github.com/1f349/cache"
	"github.com/1f349/lavender/auth"
	"github.com/1f349/lavender/conf"
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/issuer"
	"github.com/1f349/lavender/logger"
	"github.com/1f349/lavender/pages"
	"github.com/1f349/mjwt"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

var errInvalidScope = errors.New("missing required scope")

type httpServer struct {
	r          *httprouter.Router
	oauthSrv   *server.Server
	oauthMgr   *manage.Manager
	db         *database.Queries
	conf       conf.Conf
	signingKey *mjwt.Issuer
	manager    *issuer.Manager

	// mailLinkCache contains a mapping of verify uuids to user uuids
	mailLinkCache *cache.Cache[mailLinkKey, string]

	authBasic *auth.BasicLogin
	authOtp   *auth.OtpLogin
	authOAuth *auth.OAuthLogin

	authSources []auth.Provider
}

type mailLink byte

const (
	mailLinkDelete mailLink = iota
	mailLinkResetPassword
	mailLinkVerifyEmail
)

type mailLinkKey struct {
	action mailLink
	data   string
}

func SetupRouter(r *httprouter.Router, config conf.Conf, db *database.Queries, signingKey *mjwt.Issuer) {
	// remove last slash from baseUrl
	config.BaseUrl = strings.TrimRight(config.BaseUrl, "/")

	contentCache := time.Now()

	authBasic := &auth.BasicLogin{DB: db}
	authOtp := &auth.OtpLogin{DB: db}
	authOAuth := &auth.OAuthLogin{DB: db, BaseUrl: config.BaseUrl}
	authOAuth.Init()

	hs := &httpServer{
		r:          r,
		db:         db,
		conf:       config,
		signingKey: signingKey,

		mailLinkCache: cache.New[mailLinkKey, string](),

		authBasic: authBasic,
		authOtp:   authOtp,
		authOAuth: authOAuth,
		//authPasskey: &auth.PasskeyLogin{DB: db},

		authSources: []auth.Provider{
			authBasic,
			authOtp,
		},
	}

	var err error
	hs.manager, err = issuer.NewManager(config.Namespace, config.SsoServices)
	if err != nil {
		logger.Logger.Fatal("Failed to load SSO services", "err", err)
	}

	SetupOpenId(r, config.BaseUrl, signingKey)
	r.GET("/", hs.OptionalAuthentication(false, hs.Home))
	r.POST("/logout", hs.RequireAuthentication(hs.logoutPost))

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

	// login steps
	r.GET("/login", hs.OptionalAuthentication(false, hs.loginGet))
	r.POST("/login", hs.OptionalAuthentication(false, hs.loginPost))
	r.GET("/callback", hs.OptionalAuthentication(false, hs.loginCallback))

	SetupManageApps(r, hs)
	SetupManageUsers(r, hs)
	SetupOAuth2(r, hs, signingKey, db)
}

func (h *httpServer) SafeRedirect(rw http.ResponseWriter, req *http.Request) {
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
