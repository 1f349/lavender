package server

import (
	"errors"
	"github.com/1f349/cache"
	"github.com/1f349/lavender/auth"
	"github.com/1f349/lavender/auth/providers"
	"github.com/1f349/lavender/conf"
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/issuer"
	"github.com/1f349/lavender/logger"
	"github.com/1f349/lavender/mail"
	"github.com/1f349/lavender/web"
	"github.com/1f349/mjwt"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"path"
	"strings"
)

var errInvalidScope = errors.New("missing required scope")

type httpServer struct {
	r          *httprouter.Router
	oauthSrv   *server.Server
	oauthMgr   *manage.Manager
	db         *database.Queries
	conf       conf.Conf
	signingKey *mjwt.Issuer
	mailSender *mail.Mail
	manager    *issuer.Manager

	// mailLinkCache contains a mapping of verify uuids to user uuids
	mailLinkCache *cache.Cache[mailLinkKey, string]

	authSources []auth.Provider
	authButtons []auth.Button
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

func SetupRouter(r *httprouter.Router, config conf.Conf, mailSender *mail.Mail, db *database.Queries, signingKey *mjwt.Issuer) {
	// TODO: move auth provider init to main function
	// TODO: allow dynamically changing the providers based on database information
	authBasic := &providers.PasswordLogin{DB: db}
	authOtp := &providers.OtpLogin{DB: db}
	authOAuth := &providers.OAuthLogin{DB: db, BaseUrl: &config.BaseUrl}
	authOAuth.Init()
	authPasskey := &providers.PasskeyLogin{DB: db}

	authSources := []auth.Provider{
		authBasic,
		authOtp,
		authOAuth,
		authPasskey,
	}
	authButtons := make([]auth.Button, 0)
	for _, source := range authSources {
		if button, isButton := source.(auth.Button); isButton {
			authButtons = append(authButtons, button)
		}
	}

	hs := &httpServer{
		r:          r,
		db:         db,
		conf:       config,
		signingKey: signingKey,
		mailSender: mailSender,

		mailLinkCache: cache.New[mailLinkKey, string](),

		authSources: authSources,
		authButtons: authButtons,
	}

	var err error
	hs.manager, err = issuer.NewManager(config.Namespace, config.SsoServices)
	if err != nil {
		logger.Logger.Fatal("Failed to load SSO services", "err", err)
	}

	SetupOpenId(r, &config.BaseUrl, signingKey)
	r.GET("/", hs.OptionalAuthentication(false, hs.Home))
	r.POST("/logout", hs.RequireAuthentication(hs.logoutPost))

	// theme styles
	r.GET("/_astro/*filepath", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		name := params.ByName("filepath")
		if strings.Contains(name, "..") {
			http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		web.RenderWebAsset(rw, req, path.Join("_astro", name))
	})

	// login steps
	r.GET("/login", hs.OptionalAuthentication(false, hs.loginGet))
	r.POST("/login", hs.OptionalAuthentication(false, hs.loginPost))
	r.GET("/callback", hs.OptionalAuthentication(false, hs.loginCallback))

	SetupManageApps(r, hs)
	SetupManageUsers(r, hs)
	SetupOAuth2(r, hs, signingKey, db)
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
