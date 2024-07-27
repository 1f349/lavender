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
	h.flowState.Set(state, flowStateData{loginName, login, req.PostFormValue("redirect")}, time.Now().Add(15*time.Minute))

	// generate oauth2 config and redirect to authorize URL
	oa2conf := login.OAuth2Config
	oa2conf.RedirectURL = h.conf.BaseUrl + "/callback"
	nextUrl := oa2conf.AuthCodeURL(state, oauth2.SetAuthURLParam("login_name", loginUn))
	http.Redirect(rw, req, nextUrl, http.StatusFound)
}

func (h *HttpServer) loginCallback(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, userAuth UserAuth) {
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

	userAuth, err = h.updateExternalUserInfo(req, flowState.sso, token)
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
	h.SafeRedirect(rw, req)
}

func (h *HttpServer) updateExternalUserInfo(req *http.Request, sso *issuer.WellKnownOIDC, token *oauth2.Token) (UserAuth, error) {
	sessionData, err := h.fetchUserInfo(sso, token)
	if err != nil || sessionData.Subject == "" {
		return UserAuth{}, fmt.Errorf("failed to fetch user info")
	}

	err = h.DbTxError(func(tx *database.Queries) error {
		jBytes, err := json.Marshal(sessionData.UserInfo)
		if err != nil {
			return err
		}
		_, err = tx.GetUser(req.Context(), sessionData.Subject)
		if errors.Is(err, sql.ErrNoRows) {
			uEmail := sessionData.UserInfo.GetStringOrDefault("email", "unknown@localhost")
			uEmailVerified, _ := sessionData.UserInfo.GetBoolean("email_verified")
			return tx.AddUser(req.Context(), database.AddUserParams{
				Subject:       sessionData.Subject,
				Email:         uEmail,
				EmailVerified: uEmailVerified,
				Roles:         "",
				Userinfo:      string(jBytes),
				UpdatedAt:     time.Now(),
				Active:        true,
			})
		}
		uEmail := sessionData.UserInfo.GetStringOrDefault("email", "unknown@localhost")
		uEmailVerified, _ := sessionData.UserInfo.GetBoolean("email_verified")
		return tx.UpdateUserInfo(req.Context(), database.UpdateUserInfoParams{
			Email:         sessionData.Subject,
			EmailVerified: uEmailVerified,
			Userinfo:      string(jBytes),
			Subject:       uEmail,
		})
	})
	if err != nil {
		return UserAuth{}, err
	}

	// only continues if the above tx succeeds
	if err := h.DbTxError(func(tx *database.Queries) error {
		return tx.UpdateUserToken(req.Context(), database.UpdateUserTokenParams{
			AccessToken:  sql.NullString{String: token.AccessToken, Valid: true},
			RefreshToken: sql.NullString{String: token.RefreshToken, Valid: true},
			Expiry:       sql.NullTime{Time: token.Expiry, Valid: true},
			Subject:      sessionData.Subject,
		})
	}); err != nil {
		return UserAuth{}, err
	}

	return sessionData, nil
}

const twelveHours = 12 * time.Hour
const oneWeek = 7 * 24 * time.Hour

type lavenderLoginAccess struct {
	UserInfo UserInfoFields `json:"user_info"`
	auth.AccessTokenClaims
}

func (l lavenderLoginAccess) Valid() error { return l.AccessTokenClaims.Valid() }

func (l lavenderLoginAccess) Type() string { return "lavender-login-access" }

type lavenderLoginRefresh struct {
	Login string `json:"login"`
	auth.RefreshTokenClaims
}

func (l lavenderLoginRefresh) Valid() error { return l.RefreshTokenClaims.Valid() }

func (l lavenderLoginRefresh) Type() string { return "lavender-login-refresh" }

func (h *HttpServer) setLoginDataCookie(rw http.ResponseWriter, authData UserAuth, loginName string) bool {
	ps := auth.NewPermStorage()
	accId := uuid.NewString()
	gen, err := h.signingKey.GenerateJwt(authData.Subject, accId, jwt.ClaimStrings{h.conf.BaseUrl}, twelveHours, lavenderLoginAccess{
		UserInfo:          authData.UserInfo,
		AccessTokenClaims: auth.AccessTokenClaims{Perms: ps},
	})
	if err != nil {
		http.Error(rw, "Failed to generate cookie token", http.StatusInternalServerError)
		return true
	}
	ref, err := h.signingKey.GenerateJwt(authData.Subject, uuid.NewString(), jwt.ClaimStrings{h.conf.BaseUrl}, oneWeek, lavenderLoginRefresh{
		Login:              loginName,
		RefreshTokenClaims: auth.RefreshTokenClaims{AccessTokenId: accId},
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

func (h *HttpServer) readLoginAccessCookie(rw http.ResponseWriter, req *http.Request, u *UserAuth) error {
	loginData, err := readJwtCookie[lavenderLoginAccess](req, "lavender-login-access", h.signingKey.KeyStore())
	if err != nil {
		return h.readLoginRefreshCookie(rw, req, u)
	}
	*u = UserAuth{
		Subject:  loginData.Subject,
		UserInfo: loginData.Claims.UserInfo,
	}
	return nil
}

func (h *HttpServer) readLoginRefreshCookie(rw http.ResponseWriter, req *http.Request, userAuth *UserAuth) error {
	refreshData, err := readJwtCookie[lavenderLoginRefresh](req, "lavender-login-refresh", h.signingKey.KeyStore())
	if err != nil {
		return err
	}

	sso := h.manager.FindServiceFromLogin(refreshData.Claims.Login)

	var oauthToken *oauth2.Token

	err = h.DbTxError(func(tx *database.Queries) error {
		token, err := tx.GetUserToken(req.Context(), refreshData.Subject)
		if err != nil {
			return err
		}
		if !token.AccessToken.Valid || !token.RefreshToken.Valid || !token.Expiry.Valid {
			return fmt.Errorf("invalid oauth token")
		}
		oauthToken = &oauth2.Token{
			AccessToken:  token.AccessToken.String,
			RefreshToken: token.RefreshToken.String,
			Expiry:       token.Expiry.Time,
		}
		return nil
	})

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
