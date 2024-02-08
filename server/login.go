package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/issuer"
	"github.com/1f349/lavender/pages"
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
			"Origin":      req.URL.Query().Get("origin"),
			"LoginName":   cookie.Value,
		})
		return
	}
	pages.RenderPageTemplate(rw, "login", map[string]any{
		"ServiceName": h.conf.ServiceName,
		"Origin":      req.URL.Query().Get("origin"),
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
			SameSite: http.SameSiteStrictMode,
		})
		http.Redirect(rw, req, (&url.URL{
			Path: "/login",
			RawQuery: url.Values{
				"origin": []string{req.PostFormValue("origin")},
			}.Encode(),
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
		SameSite: http.SameSiteStrictMode,
	})

	// save state for use later
	state := login.Config.Namespace + ":" + uuid.NewString()
	h.flowState.Set(state, flowStateData{login}, time.Now().Add(15*time.Minute))

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

	sessionData, done := h.fetchUserInfo(rw, err, flowState.sso, token)
	if !done {
		return
	}

	if h.DbTx(rw, func(tx *database.Tx) error {
		_, err := tx.GetUser(sessionData.ID)
		if errors.Is(err, sql.ErrNoRows) {
			uEmail := sessionData.UserInfo.GetStringOrDefault("email", "unknown@localhost")
			uEmailVerified, _ := sessionData.UserInfo.GetBoolean("email_verified")
			return tx.InsertUser(sessionData.ID, uEmail, uEmailVerified, "", true)
		}
		return err
	}) {
		return
	}

	// only continues if the above tx succeeds
	auth.Data = sessionData
	if auth.SaveSessionData() != nil {
		http.Error(rw, "Failed to save session", http.StatusInternalServerError)
		return
	}

	if h.setLoginDataCookie(rw, auth.Data.ID, token) {
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h.SafeRedirect(rw, req)
}

func (h *HttpServer) setLoginDataCookie(rw http.ResponseWriter, userId string, token *oauth2.Token) bool {
	buf := new(bytes.Buffer)
	buf.WriteString(userId)
	buf.WriteByte(0)
	err := json.NewEncoder(buf).Encode(token)
	if err != nil {
		return true
	}
	encryptedData, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, h.signingKey.PublicKey(), buf.Bytes(), []byte("lavender-login-data"))
	if err != nil {
		return true
	}
	encryptedString := base64.RawStdEncoding.EncodeToString(encryptedData)
	http.SetCookie(rw, &http.Cookie{
		Name:     "lavender-login-data",
		Value:    encryptedString,
		Path:     "/",
		Expires:  time.Now().AddDate(0, 3, 0),
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	return false
}

func (h *HttpServer) readLoginDataCookie(rw http.ResponseWriter, req *http.Request, u *UserAuth) bool {
	loginCookie, err := req.Cookie("lavender-login-data")
	if err != nil {
		return false
	}
	decryptedBytes, err := base64.RawStdEncoding.DecodeString(loginCookie.Value)
	if err != nil {
		return false
	}
	decryptedData, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, h.signingKey.PrivateKey(), decryptedBytes, []byte("lavender-login-data"))
	if err != nil {
		return false
	}

	buf := bytes.NewBuffer(decryptedData)
	userId, err := buf.ReadString(0)
	if err != nil {
		return false
	}
	userId = strings.TrimSuffix(userId, "\x00")

	var token *oauth2.Token
	err = json.NewDecoder(buf).Decode(&token)
	if err != nil {
		return false
	}

	sso := h.manager.FindServiceFromLogin(userId)
	if sso == nil {
		return false
	}

	sessionData, done := h.fetchUserInfo(rw, err, sso, token)
	if !done {
		return false
	}

	u.Data = sessionData
	return true
}

func (h *HttpServer) fetchUserInfo(rw http.ResponseWriter, err error, sso *issuer.WellKnownOIDC, token *oauth2.Token) (SessionData, bool) {
	res, err := sso.OAuth2Config.Client(context.Background(), token).Get(sso.UserInfoEndpoint)
	if err != nil || res.StatusCode != http.StatusOK {
		return SessionData{}, false
	}
	defer res.Body.Close()

	var userInfoJson UserInfoFields
	if err := json.NewDecoder(res.Body).Decode(&userInfoJson); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return SessionData{}, false
	}
	subject, ok := userInfoJson.GetString("sub")
	if !ok {
		http.Error(rw, "Invalid subject", http.StatusInternalServerError)
		return SessionData{}, false
	}
	subject += "@" + sso.Config.Namespace

	displayName := userInfoJson.GetStringOrDefault("name", "Unknown Name")
	return SessionData{
		ID:          subject,
		DisplayName: displayName,
		UserInfo:    userInfoJson,
	}, true
}
