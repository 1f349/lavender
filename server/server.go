package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/1f349/cache"
	"github.com/1f349/lavender/auth"
	"github.com/1f349/lavender/auth/process"
	"github.com/1f349/lavender/auth/providers"
	"github.com/1f349/lavender/conf"
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/issuer"
	"github.com/1f349/lavender/logger"
	"github.com/1f349/lavender/mail"
	"github.com/1f349/lavender/utils"
	"github.com/1f349/lavender/web"
	"github.com/1f349/mjwt"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/oauth2"
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

	// flowState contains the flow state of 3rd party oauth2
	flowState *cache.Cache[string, flowStateData]

	authSources        []auth.Provider
	authButtons        []auth.Button
	formProviderLookup map[string]auth.Form
	authByAccessState  map[process.State][]auth.Provider
}

type flowStateData struct {
	loginName string
	sso       *issuer.WellKnownOIDC
	redirect  string
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
	// TODO: move oauth setup into oauth provider

	hs := &httpServer{
		r:          r,
		db:         db,
		conf:       config,
		signingKey: signingKey,
		mailSender: mailSender,

		mailLinkCache: cache.New[mailLinkKey, string](),
	}

	var err error
	hs.manager, err = issuer.NewManager(db, config.Namespace)
	if err != nil {
		logger.Logger.Fatal("Failed to load SSO services", "err", err)
	}

	authPassword := &providers.PasswordLogin{DB: db}
	authOtp := &providers.OtpLogin{DB: db}
	authOAuth := &providers.OAuthLogin{DB: db, BaseUrl: config.BaseUrl, Manager: hs.manager}
	authOAuth.Init()
	authPasskey := &providers.PasskeyLogin{DB: db}
	authInitial := &providers.Base{DB: db, MyNamespace: config.Namespace, Manager: hs.manager, OAuth: authOAuth}

	hs.authSources = []auth.Provider{
		authInitial,
		authPassword,
		authOtp,
		authOAuth,
		authPasskey,
	}

	r.GET("/oauth/:namespace/start", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		namespace := params.ByName("namespace")
		if !authOAuth.RedirectToAuthorize(rw, req, namespace) {
			http.Error(rw, "Invalid OAuth namespace", http.StatusBadRequest)
		}
	})
	r.GET("/oauth/:namespace/callback", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		namespace := params.ByName("namespace")
		authOAuth.OAuthCallback(rw, req, namespace, func(req *http.Request, sso *issuer.WellKnownOIDC, token *oauth2.Token) (auth.UserAuth, error) {
			resp, err := sso.OAuth2Config.Client(req.Context(), token).Get(sso.UserInfoEndpoint.String())
			if err != nil {
				return auth.UserAuth{}, err
			}
			defer resp.Body.Close()

			var userInfoJson auth.UserInfoFields
			if err := json.NewDecoder(resp.Body).Decode(&userInfoJson); err != nil {
				return auth.UserAuth{}, err
			}
			subject, ok := userInfoJson.GetString("sub")
			if !ok {
				return auth.UserAuth{}, fmt.Errorf("invalid subject")
			}
			subject += "@" + sso.Config.Namespace

			return auth.UserAuth{
				Subject:  subject,
				Factor:   process.StateBasic,
				UserInfo: userInfoJson,
			}, nil
		}, func(rw http.ResponseWriter, authData auth.UserAuth, loginName string) bool {
			// TODO: this should be using the existing auth flow calls
			return hs.setLoginDataCookie(rw, authData, loginName)
		}, func(rw http.ResponseWriter, req *http.Request) {
			// TODO: is this really needed like this?
			utils.SafeRedirect(rw, req)
		})
	})

	// build slices and maps for quick access to auth interfaces
	hs.authButtons = make([]auth.Button, 0)
	hs.formProviderLookup = make(map[string]auth.Form)
	hs.authByAccessState = make(map[process.State][]auth.Provider)
	for _, source := range hs.authSources {
		if button, isButton := source.(auth.Button); isButton {
			hs.authButtons = append(hs.authButtons, button)
		}

		if form, isForm := source.(auth.Form); isForm {
			hs.formProviderLookup[form.Name()] = form
		}

		hs.authByAccessState[source.AccessState()] = append(hs.authByAccessState[source.AccessState()], source)
	}

	SetupOpenId(r, config.BaseUrl, signingKey)
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
