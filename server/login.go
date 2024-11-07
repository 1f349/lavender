package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	auth2 "github.com/1f349/lavender/auth"
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/database/types"
	"github.com/1f349/lavender/issuer"
	"github.com/1f349/lavender/pages"
	"github.com/1f349/mjwt"
	"github.com/1f349/mjwt/auth"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"github.com/mrmelon54/pronouns"
	"golang.org/x/oauth2"
	"golang.org/x/text/language"
	"net/http"
	"net/url"
	"strings"
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

func (h *httpServer) testAuthSources(req *http.Request, user *database.User, factor auth2.Factor) map[string]bool {
	authSource := make(map[string]bool)
	data := make(map[string]any)
	for _, i := range h.authSources {
		// ignore not-supported factors
		if i.Factor()&factor == 0 {
			continue
		}
		err := i.RenderData(req.Context(), req, user, data)
		authSource[i.Name()] = err == nil
		clear(data)
	}
	return authSource
}

func (h *httpServer) loginGet(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth auth2.UserAuth) {
	if !auth.IsGuest() {
		h.SafeRedirect(rw, req)
		return
	}

	cookie, err := req.Cookie("lavender-login-name")
	if err == nil && cookie.Valid() == nil {
		user, err := h.db.GetUser(req.Context(), auth.Subject)
		var userPtr *database.User
		switch {
		case err == nil:
			userPtr = &user
		case errors.Is(err, sql.ErrNoRows):
			userPtr = nil
		default:
			http.Error(rw, "Internal server error", http.StatusInternalServerError)
			return
		}

		fmt.Printf("%#v\n", h.testAuthSources(req, userPtr, auth2.FactorFirst))

		pages.RenderPageTemplate(rw, "login-memory", map[string]any{
			"ServiceName": h.conf.ServiceName,
			"LoginName":   cookie.Value,
			"Redirect":    req.URL.Query().Get("redirect"),
			"Source":      "start",
			"Auth":        h.testAuthSources(req, userPtr, auth2.FactorFirst),
		})
		return
	}

	// render different page sources
	pages.RenderPageTemplate(rw, "login", map[string]any{
		"ServiceName": h.conf.ServiceName,
		"LoginName":   "",
		"Redirect":    req.URL.Query().Get("redirect"),
		"Source":      "start",
		"Auth":        h.testAuthSources(req, nil, auth2.FactorFirst),
	})
}

func (h *httpServer) loginPost(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth auth2.UserAuth) {
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

	// append local namespace if @ is missing
	n := strings.IndexByte(loginName, '@')
	if n < 0 {
		// correct the @ index
		n = len(loginName)
		loginName += "@" + h.conf.Namespace
	}

	login := h.manager.FindServiceFromLogin(loginName)
	if login == nil {
		http.Error(rw, "No login service defined for this username", http.StatusBadRequest)
		return
	}

	// the @ must exist if the service is defined
	loginUn := loginName[:n]

	ctx := auth2.WithWellKnown(req.Context(), login)
	ctx = context.WithValue(ctx, "login_username", loginUn)
	ctx = context.WithValue(ctx, "login_full", loginName)

	// TODO(melon): only do if remember-me is enabled
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

	var redirectError auth2.RedirectError

	// if the login is the local server
	if login == issuer.MeWellKnown {
		// TODO(melon): work on this
		err := h.authBasic.AttemptLogin(ctx, req, nil)
		switch {
		case errors.As(err, &redirectError):
			http.Redirect(rw, req, redirectError.Target, redirectError.Code)
			return
		}
		return
	}

	err := h.authOAuth.AttemptLogin(ctx, req, nil)
	switch {
	case errors.As(err, &redirectError):
		http.Redirect(rw, req, redirectError.Target, redirectError.Code)
		return
	}
}

func (h *httpServer) loginCallback(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, userAuth auth2.UserAuth) {
	h.authOAuth.OAuthCallback(rw, req, h.updateExternalUserInfo, h.setLoginDataCookie, h.SafeRedirect)
}

func (h *httpServer) updateExternalUserInfo(req *http.Request, sso *issuer.WellKnownOIDC, token *oauth2.Token) (auth2.UserAuth, error) {
	sessionData, err := h.fetchUserInfo(sso, token)
	if err != nil || sessionData.Subject == "" {
		return auth2.UserAuth{}, fmt.Errorf("failed to fetch user info")
	}

	// TODO(melon): fix this to use a merging of lavender and tulip auth

	// find an existing user with the matching oauth2 namespace and subject
	var userSubject string
	err = h.DbTxError(func(tx *database.Queries) (err error) {
		userSubject, err = tx.FindUserByAuth(req.Context(), database.FindUserByAuthParams{
			AuthType:      types.AuthTypeOauth2,
			AuthNamespace: sso.Namespace,
			AuthUser:      sessionData.Subject,
		})
		return
	})
	switch {
	case err == nil:
		// user already exists
		err = h.DbTxError(func(tx *database.Queries) error {
			return h.updateOAuth2UserProfile(req.Context(), tx, sessionData)
		})
		return auth2.UserAuth{
			Subject:  userSubject,
			Factor:   auth2.FactorAuthorized,
			UserInfo: sessionData.UserInfo,
		}, err
	case errors.Is(err, sql.ErrNoRows):
		// happy path for registration
		break
	default:
		// another error occurred
		return auth2.UserAuth{}, err
	}

	// guard for disabled registration
	if !sso.Config.Registration {
		return auth2.UserAuth{}, fmt.Errorf("registration is not enabled for this authentication source")
	}

	// TODO(melon): rework this
	name := sessionData.UserInfo.GetStringOrDefault("name", "Unknown User")
	uEmail := sessionData.UserInfo.GetStringOrDefault("email", "unknown@localhost")
	uEmailVerified, _ := sessionData.UserInfo.GetBoolean("email_verified")

	err = h.DbTxError(func(tx *database.Queries) (err error) {
		userSubject, err = tx.AddOAuthUser(req.Context(), database.AddOAuthUserParams{
			Email:         uEmail,
			EmailVerified: uEmailVerified,
			Name:          name,
			Username:      sessionData.UserInfo.GetStringFromKeysOrEmpty("login", "preferred_username"),
			AuthNamespace: sso.Namespace,
			AuthUser:      sessionData.UserInfo.GetStringOrEmpty("sub"),
		})
		if err != nil {
			return err
		}

		// if adding the user succeeds then update the profile
		return h.updateOAuth2UserProfile(req.Context(), tx, sessionData)
	})
	if err != nil {
		return auth2.UserAuth{}, err
	}

	// only continues if the above tx succeeds
	if err := h.DbTxError(func(tx *database.Queries) error {
		return tx.UpdateUserToken(req.Context(), database.UpdateUserTokenParams{
			AccessToken:  sql.NullString{String: token.AccessToken, Valid: true},
			RefreshToken: sql.NullString{String: token.RefreshToken, Valid: true},
			TokenExpiry:  sql.NullTime{Time: token.Expiry, Valid: true},
			Subject:      sessionData.Subject,
		})
	}); err != nil {
		return auth2.UserAuth{}, err
	}

	// TODO(melon): this feels bad
	sessionData = auth2.UserAuth{
		Subject:  userSubject,
		Factor:   auth2.FactorAuthorized,
		UserInfo: sessionData.UserInfo,
	}

	return sessionData, nil
}

func (h *httpServer) updateOAuth2UserProfile(ctx context.Context, tx *database.Queries, sessionData auth2.UserAuth) error {
	// all of these updates must succeed
	return tx.UseTx(ctx, func(tx *database.Queries) error {
		name := sessionData.UserInfo.GetStringOrDefault("name", "Unknown User")

		err := tx.ModifyUserRemoteLogin(ctx, database.ModifyUserRemoteLoginParams{
			Login:      sessionData.UserInfo.GetStringFromKeysOrEmpty("login", "preferred_username"),
			ProfileUrl: sessionData.UserInfo.GetStringOrEmpty("profile"),
			Subject:    sessionData.Subject,
		})
		if err != nil {
			return err
		}

		pronoun, err := pronouns.FindPronoun(sessionData.UserInfo.GetStringOrEmpty("pronouns"))
		if err != nil {
			pronoun = pronouns.TheyThem
		}
		locale, err := language.Parse(sessionData.UserInfo.GetStringOrEmpty("locale"))
		if err != nil {
			locale = language.AmericanEnglish
		}

		return tx.ModifyProfile(ctx, database.ModifyProfileParams{
			Name:      name,
			Picture:   sessionData.UserInfo.GetStringOrEmpty("profile"),
			Website:   sessionData.UserInfo.GetStringOrEmpty("website"),
			Pronouns:  types.UserPronoun{Pronoun: pronoun},
			Birthdate: sessionData.UserInfo.GetNullDate("birthdate"),
			Zone:      sessionData.UserInfo.GetStringOrDefault("zoneinfo", "UTC"),
			Locale:    types.UserLocale{Tag: locale},
			UpdatedAt: time.Now(),
			Subject:   sessionData.Subject,
		})
	})
}

const twelveHours = 12 * time.Hour
const oneWeek = 7 * 24 * time.Hour

type lavenderLoginAccess struct {
	UserInfo auth2.UserInfoFields `json:"user_info"`
	Factor   auth2.Factor         `json:"factor"`
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

func (h *httpServer) setLoginDataCookie(rw http.ResponseWriter, authData auth2.UserAuth, loginName string) bool {
	ps := auth.NewPermStorage()
	accId := uuid.NewString()
	gen, err := h.signingKey.GenerateJwt(authData.Subject, accId, jwt.ClaimStrings{h.conf.BaseUrl}, twelveHours, lavenderLoginAccess{
		UserInfo:          authData.UserInfo,
		Factor:            authData.Factor,
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

func (h *httpServer) readLoginAccessCookie(rw http.ResponseWriter, req *http.Request, u *auth2.UserAuth) error {
	loginData, err := readJwtCookie[lavenderLoginAccess](req, "lavender-login-access", h.signingKey.KeyStore())
	if err != nil {
		return h.readLoginRefreshCookie(rw, req, u)
	}
	*u = auth2.UserAuth{
		Subject:  loginData.Subject,
		Factor:   loginData.Claims.Factor,
		UserInfo: loginData.Claims.UserInfo,
	}
	return nil
}

func (h *httpServer) readLoginRefreshCookie(rw http.ResponseWriter, req *http.Request, userAuth *auth2.UserAuth) error {
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

func (h *httpServer) fetchUserInfo(sso *issuer.WellKnownOIDC, token *oauth2.Token) (auth2.UserAuth, error) {
	res, err := sso.OAuth2Config.Client(context.Background(), token).Get(sso.UserInfoEndpoint)
	if err != nil || res.StatusCode != http.StatusOK {
		return auth2.UserAuth{}, fmt.Errorf("request failed")
	}
	defer res.Body.Close()

	var userInfoJson auth2.UserInfoFields
	if err := json.NewDecoder(res.Body).Decode(&userInfoJson); err != nil {
		return auth2.UserAuth{}, err
	}
	subject, ok := userInfoJson.GetString("sub")
	if !ok {
		return auth2.UserAuth{}, fmt.Errorf("invalid subject")
	}

	// TODO(melon): there is no need for this
	//subject += "@" + sso.Config.Namespace

	return auth2.UserAuth{
		Subject:  subject,
		Factor:   auth2.FactorAuthorized,
		UserInfo: userInfoJson,
	}, nil
}
