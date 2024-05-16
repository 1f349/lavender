package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/issuer"
	"github.com/1f349/lavender/pages"
	"github.com/1f349/mjwt"
	"github.com/1f349/mjwt/auth"
	"github.com/1f349/mjwt/claims"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (h *HttpServer) loginGet(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	if !auth.IsGuest() {
		h.SafeRedirect(rw, req)
		return
	}

	cookie, err := req.Cookie("lavender-login-name")
	if err == nil && cookie.Valid() == nil {
		pages.RenderPageTemplate(rw, "login-memory", map[string]any{
			"ServiceName": h.conf.ServiceName,
			"LoginName":   cookie.Value,
			"Redirect":    req.URL.Query().Get("redirect"),
		})
		return
	}
	pages.RenderPageTemplate(rw, "login", map[string]any{
		"ServiceName": h.conf.ServiceName,
		"Redirect":    req.URL.Query().Get("redirect"),
	})
}

func (h *HttpServer) loginPost(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	if !auth.IsGuest() {
		h.SafeRedirect(rw, req)
		return
	}

	if req.PostFormValue("not-you") == "1" {
		http.SetCookie(rw, &http.Cookie{
			Name:     "lavender-login-name",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(rw, req, (&url.URL{
			Path: "/login",
		}).String(), http.StatusFound)
		return
	}
	loginName := req.PostFormValue("loginname")
	login := h.manager.FindServiceFromLogin(loginName)
	if login == nil {
		http.Error(rw, "No login service defined for this username", http.StatusBadRequest)
		return
	}
	// the @ must exist if the service is defined
	n := strings.IndexByte(loginName, '@')
	loginUn := loginName[:n]

	now := time.Now()
	future := now.AddDate(1, 0, 0)
	http.SetCookie(rw, &http.Cookie{
		Name:     "lavender-login-name",
		Value:    loginName,
		Path:     "/",
		Expires:  future,
		MaxAge:   int(future.Sub(now).Seconds()),
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// save state for use later
	state := login.Config.Namespace + ":" + uuid.NewString()
	h.flowState.Set(state, flowStateData{login, req.PostFormValue("redirect")}, time.Now().Add(15*time.Minute))

	// generate oauth2 config and redirect to authorize URL
	oa2conf := login.OAuth2Config
	oa2conf.RedirectURL = h.conf.BaseUrl + "/callback"
	nextUrl := oa2conf.AuthCodeURL(state, oauth2.SetAuthURLParam("login_name", loginUn))
	http.Redirect(rw, req, nextUrl, http.StatusFound)
}

func (h *HttpServer) loginCallback(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	flowState, ok := h.flowState.Get(req.FormValue("state"))
	if !ok {
		http.Error(rw, "Invalid flow state", http.StatusBadRequest)
		return
	}
	token, err := flowState.sso.OAuth2Config.Exchange(context.Background(), req.FormValue("code"), oauth2.SetAuthURLParam("redirect_uri", h.conf.BaseUrl+"/callback"))
	if err != nil {
		http.Error(rw, "Failed to exchange code for token", http.StatusInternalServerError)
		return
	}

	sessionData, err := h.fetchUserInfo(flowState.sso, token)
	if err != nil || sessionData.Subject == "" {
		http.Error(rw, "Failed to fetch user info", http.StatusInternalServerError)
		return
	}

	if h.DbTx(rw, func(tx *database.Tx) error {
		jBytes, err := json.Marshal(sessionData.UserInfo)
		if err != nil {
			return err
		}
		_, err = tx.GetUser(sessionData.Subject)
		if errors.Is(err, sql.ErrNoRows) {
			uEmail := sessionData.UserInfo.GetStringOrDefault("email", "unknown@localhost")
			uEmailVerified, _ := sessionData.UserInfo.GetBoolean("email_verified")
			return tx.InsertUser(sessionData.Subject, uEmail, uEmailVerified, "", string(jBytes), true)
		}
		uEmail := sessionData.UserInfo.GetStringOrDefault("email", "unknown@localhost")
		uEmailVerified, _ := sessionData.UserInfo.GetBoolean("email_verified")
		return tx.UpdateUserInfo(sessionData.Subject, uEmail, uEmailVerified, string(jBytes))
	}) {
		return
	}

	// only continues if the above tx succeeds
	auth = sessionData

	if h.DbTx(rw, func(tx *database.Tx) error {
		return tx.UpdateUserToken(auth.Subject, token.AccessToken, token.RefreshToken, token.Expiry)
	}) {
		return
	}

	if h.setLoginDataCookie(rw, auth) {
		http.Error(rw, "Failed to save login cookie", http.StatusInternalServerError)
		return
	}
	if flowState.redirect != "" {
		req.Form.Set("redirect", flowState.redirect)
	}
	h.SafeRedirect(rw, req)
}

const oneYear = 365 * 24 * time.Hour

type lavenderLoginData struct {
	UserInfo UserInfoFields `json:"user_info"`
	auth.AccessTokenClaims
}

func (l lavenderLoginData) Valid() error { return nil }

func (l lavenderLoginData) Type() string { return "lavender-login-data" }

func (h *HttpServer) setLoginDataCookie(rw http.ResponseWriter, authData UserAuth) bool {
	ps := claims.NewPermStorage()
	gen, err := h.signingKey.GenerateJwt(authData.Subject, uuid.NewString(), jwt.ClaimStrings{h.conf.BaseUrl}, oneYear, lavenderLoginData{
		UserInfo:          authData.UserInfo,
		AccessTokenClaims: auth.AccessTokenClaims{Perms: ps},
	})
	if err != nil {
		http.Error(rw, "Failed to generate cookie token", http.StatusInternalServerError)
		return true
	}
	http.SetCookie(rw, &http.Cookie{
		Name:     "lavender-login-data",
		Value:    gen,
		Path:     "/",
		Expires:  time.Now().AddDate(0, 3, 0),
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return false
}

func (h *HttpServer) readLoginDataCookie(req *http.Request, u *UserAuth) error {
	loginCookie, err := req.Cookie("lavender-login-data")
	if err != nil {
		return err
	}
	_, b, err := mjwt.ExtractClaims[lavenderLoginData](h.signingKey, loginCookie.Value)
	if err != nil {
		return err
	}
	*u = UserAuth{
		Subject:  b.Subject,
		UserInfo: b.Claims.UserInfo,
	}
	return nil
}

func (h *HttpServer) fetchUserInfo(sso *issuer.WellKnownOIDC, token *oauth2.Token) (UserAuth, error) {
	res, err := sso.OAuth2Config.Client(context.Background(), token).Get(sso.UserInfoEndpoint)
	if err != nil || res.StatusCode != http.StatusOK {
		return UserAuth{}, fmt.Errorf("request failed")
	}
	defer res.Body.Close()

	var userInfoJson UserInfoFields
	if err := json.NewDecoder(res.Body).Decode(&userInfoJson); err != nil {
		return UserAuth{}, err
	}
	subject, ok := userInfoJson.GetString("sub")
	if !ok {
		return UserAuth{}, fmt.Errorf("invalid subject")
	}
	subject += "@" + sso.Config.Namespace

	return UserAuth{
		Subject:  subject,
		UserInfo: userInfoJson,
	}, nil
}
