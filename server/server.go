package server

import (
	"errors"
	"github.com/1f349/cache"
	clientStore "github.com/1f349/lavender/client-store"
	"github.com/1f349/lavender/conf"
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/issuer"
	"github.com/1f349/lavender/pages"
	scope2 "github.com/1f349/lavender/scope"
	"github.com/1f349/mjwt"
	"github.com/go-oauth2/oauth2/v4/generates"
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

type httpServer struct {
	r          *httprouter.Router
	oauthSrv   *server.Server
	oauthMgr   *manage.Manager
	db         *database.Queries
	conf       conf.Conf
	signingKey *mjwt.Issuer
	manager    *issuer.Manager

	// flowState contains the
	flowState *cache.Cache[string, flowStateData]

	// mailLinkCache contains a mapping of verify uuids to user uuids
	mailLinkCache *cache.Cache[mailLinkKey, string]
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

func SetupRouter(r *httprouter.Router, config conf.Conf, db *database.Queries, signingKey *mjwt.Issuer) {
	// remove last slash from baseUrl
	config.BaseUrl = strings.TrimRight(config.BaseUrl, "/")

	contentCache := time.Now()

	hs := &httpServer{
		r:          r,
		db:         db,
		conf:       config,
		signingKey: signingKey,

		flowState: cache.New[string, flowStateData](),

		mailLinkCache: cache.New[mailLinkKey, string](),
	}

	oauthManager := manage.NewManager()
	oauthManager.MapAuthorizeGenerate(generates.NewAuthorizeGenerate())
	oauthManager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	oauthManager.MustTokenStorage(store.NewMemoryTokenStore())
	oauthManager.MapAccessGenerate(NewMJWTAccessGenerate(signingKey, db))
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

	ssoManager := issuer.NewManager(config.SsoServices)

	SetupOpenId(r, config.BaseUrl, signingKey)
	r.POST("/logout", hs.RequireAuthentication(fu))

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

	SetupManageApps(r)
	SetupManageUsers(r)
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
