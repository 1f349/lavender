package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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

	res, err := flowState.sso.OAuth2Config.Client(context.Background(), token).Get(flowState.sso.UserInfoEndpoint)
	if err != nil || res.StatusCode != 200 {
		rw.WriteHeader(http.StatusInternalServerError)
		if err != nil {
			_, _ = rw.Write([]byte(err.Error()))
		} else {
			_, _ = rw.Write([]byte(res.Status))
		}
		return
	}
	defer res.Body.Close()

	var userInfoJson map[string]any
	if err := json.NewDecoder(res.Body).Decode(&userInfoJson); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	subject, ok := userInfoJson["sub"].(string)
	if !ok {
		http.Error(rw, "Invalid subject", http.StatusInternalServerError)
		return
	}
	subject += "@" + flowState.sso.Config.Namespace

	displayName, ok := userInfoJson["name"].(string)
	if !ok {
		displayName = "Unknown Name"
	}

	// only continues if the above tx succeeds
	auth.Data = SessionData{
		ID:          subject,
		DisplayName: displayName,
		UserInfo:    userInfoJson,
	}
	if auth.SaveSessionData() != nil {
		http.Error(rw, "Failed to save session", http.StatusInternalServerError)
		return
	}

	if h.setLoginDataCookie(rw, auth.Data.ID) {
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h.SafeRedirect(rw, req)
}

func (h *HttpServer) setLoginDataCookie(rw http.ResponseWriter, userId string) bool {
	encryptedData, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, h.signingKey.PublicKey(), []byte(userId), []byte("login-data"))
	if err != nil {
		return true
	}
	encryptedString := base64.RawStdEncoding.EncodeToString(encryptedData)
	http.SetCookie(rw, &http.Cookie{
		Name:     "login-data",
		Value:    encryptedString,
		Path:     "/",
		Expires:  time.Now().AddDate(0, 3, 0),
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	return false
}
