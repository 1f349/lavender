package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/1f349/lavender/auth"
	"github.com/1f349/lavender/auth/authContext"
	"github.com/1f349/lavender/auth/process"
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/issuer"
	"github.com/1f349/lavender/logger"
	"github.com/1f349/lavender/utils"
	"github.com/1f349/lavender/web"
	"github.com/1f349/mjwt"
	mjwtAuth "github.com/1f349/mjwt/auth"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/oauth2"
	"html/template"
	"net/http"
	"net/url"
	"time"
)

// getUserLoginName finds the `login_name` query parameter within the `/authorize` redirect url
func getUserLoginName(req *http.Request) string {
	q := req.URL.Query()
	if !q.Has("redirect") {
		return ""
	}
	originUrl, err := url.ParseRequestURI(q.Get("redirect"))
	if err != nil {
		return ""
	}
	if originUrl.Path != "/authorize" {
		return ""
	}
	return originUrl.Query().Get("login_name")
}

func (h *httpServer) getAuthWithState(state process.State) auth.Provider {
	for _, i := range h.authSources {
		if i.AccessState() == state {
			return i
		}
	}
	return nil
}

func (h *httpServer) renderAuthTemplate(req *http.Request, provider auth.Form, processData process.LoginProcessData) (template.HTML, error) {
	tmpCtx := authContext.NewTemplateContext(req, new(database.User), processData)

	err := provider.RenderTemplate(tmpCtx)
	if err != nil {
		return "", err
	}

	w := new(bytes.Buffer)
	if web.RenderPageTemplate(w, "auth/"+provider.Name(), tmpCtx.Data()) {
		return template.HTML(w.Bytes()), nil
	}
	return "", fmt.Errorf("failed to render auth template")
}

func (h *httpServer) loginGet(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, userAuth auth.UserAuth) {
	if !userAuth.IsGuest() {
		utils.SafeRedirect(rw, req)
		return
	}

	var processData process.LoginProcessData

	jwtCookie, err := readJwtCookie[process.LoginProcessData](req, "lavender-login-process", h.signingKey.KeyStore())
	if err == nil {
		processData = jwtCookie.Claims
	}

	// TODO: some of this should be more like tulip

	buttonCtx := authContext.NewTemplateContext(req, new(database.User), processData)

	buttonTemplates := make([]template.HTML, 0, len(h.authButtons))
	for i := range h.authButtons {
		h.authButtons[i].RenderButtonTemplate(buttonCtx)
		if buttonCtx.Data() != nil {
			// TODO: finish the buttons here
			buf := new(bytes.Buffer)
			web.RenderPageTemplate(buf, "auth-buttons/"+h.authButtons[i].Name(), buttonCtx.Data())
			buttonTemplates = append(buttonTemplates, template.HTML(buf.String()))
			buttonCtx.Render(nil)
		}
	}

	provider := h.getAuthWithState(processData.State)

	var renderTemplate template.HTML

	// Maybe the admin has disabled some login providers but does have a button based provider available?
	form, ok := provider.(auth.Form)
	if provider != nil && ok {
		renderTemplate, err = h.renderAuthTemplate(req, form, processData)
		if err != nil {
			logger.Logger.Warn("No provider for login")
			web.RenderPageTemplate(rw, "login-error", struct {
				Error string `json:"error"`
			}{Error: "No available provider for login"})
			return
		}
	}

	// render different page sources
	web.RenderPageTemplate(rw, "login", map[string]any{
		"ServiceName":  h.conf.ServiceName,
		"LoginName":    "",
		"Redirect":     req.URL.Query().Get("redirect"),
		"Source":       "start",
		"AuthTemplate": renderTemplate,
		"AuthButtons":  buttonTemplates,
	})
}

func (h *httpServer) loginPost(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth2 auth.UserAuth) {
	if !auth2.IsGuest() {
		utils.SafeRedirect(rw, req)
		return
	}

	var processData process.LoginProcessData
	jwtCookie, err := readJwtCookie[process.LoginProcessData](req, "lavender-login-process", h.signingKey.KeyStore())
	if err == nil {
		processData = jwtCookie.Claims
	}

	authForm := h.formProviderLookup[req.PostFormValue("provider")]
	if authForm == nil {
		http.Error(rw, "Invalid auth provider", http.StatusBadRequest)
		return
	}

	if processData.State != authForm.AccessState() {
		http.Redirect(rw, req, "/login", http.StatusFound)
		return
	}

	// TODO: rewrite
	formContext := authContext.NewFormContext(req, nil, rw)
	err = authForm.AttemptLogin(formContext)

	var redirectError auth.RedirectError
	if errors.As(err, &redirectError) {
		http.Redirect(rw, req, redirectError.Target, redirectError.Code)
		return
	}

	// ResponseWriter has been hijacked so we stop processing here
	if formContext.HijackCalled() {
		return
	}

	// TODO: idk why login process data isn't working properly
	processData = formContext.GetLoginProcessData()
	if h.setLoginProcessCookie(rw, processData) {
		return
	}

	// TODO: figure this out
	logger.Logger.Debug("POST /login: form render data: ", formContext.Data())
	http.Redirect(rw, req, h.conf.BaseUrl.JoinPath("login").String(), http.StatusFound)
}

func (h *httpServer) setLoginProcessCookie(rw http.ResponseWriter, data process.LoginProcessData) bool {
	gen, err := h.signingKey.GenerateJwt("login-process", uuid.NewString(), jwt.ClaimStrings{h.conf.BaseUrl.String()}, time.Hour, data)
	if err != nil {
		http.Error(rw, "Failed to generate cookie token", http.StatusInternalServerError)
		return true
	}
	http.SetCookie(rw, &http.Cookie{
		Name:     "lavender-login-process",
		Value:    gen,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return false
}

func (h *httpServer) loginCallback(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, _ auth.UserAuth) {
	flowState, ok := h.flowState.Get(req.FormValue("state"))
	if !ok {
		http.Error(rw, "Invalid flow state", http.StatusBadRequest)
		return
	}
	token, err := flowState.sso.OAuth2Config.Exchange(context.Background(), req.FormValue("code"), oauth2.SetAuthURLParam("redirect_uri", h.conf.BaseUrl.JoinPath("callback").String()))
	if err != nil {
		http.Error(rw, "Failed to exchange code for token", http.StatusInternalServerError)
		return
	}

	userAuth, err := h.updateExternalUserInfo(req, flowState.sso, token)
	if err != nil {
		http.Error(rw, "Failed to update external user info", http.StatusInternalServerError)
		return
	}

	if h.setLoginDataCookie(rw, userAuth, flowState.loginName) {
		http.Error(rw, "Failed to save login cookie", http.StatusInternalServerError)
		return
	}
	if flowState.redirect != "" {
		req.Form.Set("redirect", flowState.redirect)
	}
	utils.SafeRedirect(rw, req)
}

const twelveHours = 12 * time.Hour
const oneWeek = 7 * 24 * time.Hour

type lavenderLoginAccess struct {
	UserInfo auth.UserInfoFields `json:"user_info"`
	Factor   process.State       `json:"factor"`
	mjwtAuth.AccessTokenClaims
}

func (l lavenderLoginAccess) Valid() error { return l.AccessTokenClaims.Valid() }

func (l lavenderLoginAccess) Type() string { return "lavender-login-access" }

type lavenderLoginRefresh struct {
	Login string `json:"login"`
	mjwtAuth.RefreshTokenClaims
}

func (l lavenderLoginRefresh) Valid() error { return l.RefreshTokenClaims.Valid() }

func (l lavenderLoginRefresh) Type() string { return "lavender-login-refresh" }

func (h *httpServer) setLoginDataCookie(rw http.ResponseWriter, authData auth.UserAuth, loginName string) bool {
	ps := mjwtAuth.NewPermStorage()
	accId := uuid.NewString()
	gen, err := h.signingKey.GenerateJwt(authData.Subject, accId, jwt.ClaimStrings{h.conf.BaseUrl.String()}, twelveHours, lavenderLoginAccess{
		UserInfo:          authData.UserInfo,
		Factor:            authData.Factor,
		AccessTokenClaims: mjwtAuth.AccessTokenClaims{Perms: ps},
	})
	if err != nil {
		http.Error(rw, "Failed to generate cookie token", http.StatusInternalServerError)
		return true
	}
	ref, err := h.signingKey.GenerateJwt(authData.Subject, uuid.NewString(), jwt.ClaimStrings{h.conf.BaseUrl.String()}, oneWeek, lavenderLoginRefresh{
		Login:              loginName,
		RefreshTokenClaims: mjwtAuth.RefreshTokenClaims{AccessTokenId: accId},
	})
	if err != nil {
		http.Error(rw, "Failed to generate cookie token", http.StatusInternalServerError)
		return true
	}
	http.SetCookie(rw, &http.Cookie{
		Name:     "lavender-login-access",
		Value:    gen,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(rw, &http.Cookie{
		Name:     "lavender-login-refresh",
		Value:    ref,
		Path:     "/",
		Expires:  time.Now().AddDate(0, 0, 10),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return false
}

func readJwtCookie[T mjwt.Claims](req *http.Request, cookieName string, signingKey *mjwt.KeyStore) (mjwt.BaseTypeClaims[T], error) {
	loginCookie, err := req.Cookie(cookieName)
	if err != nil {
		return mjwt.BaseTypeClaims[T]{}, err
	}
	_, b, err := mjwt.ExtractClaims[T](signingKey, loginCookie.Value)
	if err != nil {
		return mjwt.BaseTypeClaims[T]{}, err
	}
	return b, nil
}

func (h *httpServer) readLoginAccessCookie(rw http.ResponseWriter, req *http.Request, u *auth.UserAuth) error {
	loginData, err := readJwtCookie[lavenderLoginAccess](req, "lavender-login-access", h.signingKey.KeyStore())
	if err != nil {
		return h.readLoginRefreshCookie(rw, req, u)
	}
	*u = auth.UserAuth{
		Subject:  loginData.Subject,
		Factor:   loginData.Claims.Factor,
		UserInfo: loginData.Claims.UserInfo,
	}
	return nil
}

func (h *httpServer) readLoginRefreshCookie(rw http.ResponseWriter, req *http.Request, userAuth *auth.UserAuth) error {
	refreshData, err := readJwtCookie[lavenderLoginRefresh](req, "lavender-login-refresh", h.signingKey.KeyStore())
	if err != nil {
		return err
	}

	_, namespace, err := utils.ParseLoginName(refreshData.Claims.Login)
	if err != nil {
		return err
	}

	sso := h.manager.GetService(namespace)
	if sso == nil {
		return fmt.Errorf("invalid namespace: %s", namespace)
	}

	var oauthToken *oauth2.Token

	err = h.DbTxError(func(tx *database.Queries) error {
		token, err := tx.GetUserToken(req.Context(), refreshData.Subject)
		if err != nil {
			return err
		}
		if !token.AccessToken.Valid || !token.RefreshToken.Valid || !token.TokenExpiry.Valid {
			return fmt.Errorf("invalid oauth token")
		}
		oauthToken = &oauth2.Token{
			AccessToken:  token.AccessToken.String,
			RefreshToken: token.RefreshToken.String,
			Expiry:       token.TokenExpiry.Time,
		}
		return nil
	})

	// TODO: not sure how I want to handle this yet...
	*userAuth, err = h.updateExternalUserInfo(req, sso, oauthToken)
	if err != nil {
		return err
	}

	if h.setLoginDataCookie(rw, *userAuth, refreshData.Claims.Login) {
		http.Error(rw, "Failed to save login cookie", http.StatusInternalServerError)
		return fmt.Errorf("failed to save login cookie: %w", ErrAuthHttpError)
	}
	return nil
}

// TODO: not sure how I want to handle this yet...
func (h *httpServer) updateExternalUserInfo(req *http.Request, sso *issuer.WellKnownOIDC, token *oauth2.Token) (auth.UserAuth, error) {
	return auth.UserAuth{}, fmt.Errorf("no")
}
