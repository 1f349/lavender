package server

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/1f349/lavender/server/pages"
	"github.com/MrMelon54/mjwt/auth"
	"github.com/MrMelon54/mjwt/claims"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"strings"
	"time"
)

func (h *HttpServer) flowPopup(rw http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	err := pages.FlowTemplates.Execute(rw, map[string]any{
		"ServiceName": h.conf.ServiceName,
		"Origin":      req.URL.Query().Get("origin"),
	})
	if err != nil {
		log.Printf("Failed to render page: %s\n", err)
	}
}

func (h *HttpServer) flowPopupPost(rw http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	loginName := req.PostFormValue("loginname")
	login := h.manager.FindServiceFromLogin(loginName)
	if login == nil {
		http.Error(rw, "No login service defined for this username", http.StatusBadRequest)
		return
	}

	targetOrigin := req.PostFormValue("origin")
	if _, found := h.services[targetOrigin]; !found {
		http.Error(rw, "Invalid target origin", http.StatusBadRequest)
		return
	}

	// save state for use later
	state := login.Config.Namespace + ":" + uuid.NewString()
	h.flowState.Set(state, flowStateData{
		login,
		targetOrigin,
	}, time.Now().Add(15*time.Minute))

	// generate oauth2 config and redirect to authorize URL
	oa2conf := login.OAuth2Config
	oa2conf.RedirectURL = h.conf.BaseUrl + "/callback"
	nextUrl := oa2conf.AuthCodeURL(state, oauth2.SetAuthURLParam("login_name", loginName))
	http.Redirect(rw, req, nextUrl, http.StatusFound)
}

func (h *HttpServer) flowCallback(rw http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	err := req.ParseForm()
	if err != nil {
		http.Error(rw, "Error parsing form", http.StatusBadRequest)
		return
	}

	q := req.URL.Query()
	state := q.Get("state")
	n := strings.IndexByte(state, ':')
	if !h.manager.CheckNamespace(state[:n]) {
		http.Error(rw, "Invalid state", http.StatusBadRequest)
		return
	}
	v, found := h.flowState.Get(state)
	if !found {
		http.Error(rw, "Invalid state", http.StatusBadRequest)
		return
	}

	oa2conf := v.sso.OAuth2Config
	oa2conf.RedirectURL = h.conf.BaseUrl + "/callback"
	exchange, err := oa2conf.Exchange(context.Background(), q.Get("code"))
	if err != nil {
		fmt.Println("Failed exchange:", err)
		http.Error(rw, "Failed to exchange code", http.StatusInternalServerError)
		return
	}
	client := v.sso.OAuth2Config.Client(req.Context(), exchange)
	v2, err := client.Get(v.sso.UserInfoEndpoint)
	if err != nil {
		fmt.Println("Failed to get userinfo:", err)
		http.Error(rw, "Failed to get userinfo", http.StatusInternalServerError)
		return
	}
	defer v2.Body.Close()
	if v2.StatusCode != http.StatusOK {
		http.Error(rw, "Failed to get userinfo", http.StatusInternalServerError)
		return
	}

	var v3 map[string]any
	if err = json.NewDecoder(v2.Body).Decode(&v3); err != nil {
		fmt.Println("Failed to decode userinfo:", err)
		http.Error(rw, "Failed to decode userinfo JSON", http.StatusInternalServerError)
		return
	}

	sub, ok := v3["sub"].(string)
	if !ok {
		http.Error(rw, "Invalid value in userinfo", http.StatusInternalServerError)
		return
	}
	aud, ok := v3["aud"].(string)
	if !ok {
		http.Error(rw, "Invalid value in userinfo", http.StatusInternalServerError)
		return
	}

	ps := claims.NewPermStorage()
	nsSub := sub + "@" + v.sso.Config.Namespace
	ati := uuid.NewString()
	accessToken, err := h.signer.GenerateJwt(nsSub, ati, jwt.ClaimStrings{aud}, 15*time.Minute, auth.AccessTokenClaims{
		Perms: ps,
	})
	if err != nil {
		http.Error(rw, "Error generating access token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := h.signer.GenerateJwt(nsSub, uuid.NewString(), jwt.ClaimStrings{aud}, 15*time.Minute, auth.RefreshTokenClaims{AccessTokenId: ati})
	if err != nil {
		http.Error(rw, "Error generating refresh token", http.StatusInternalServerError)
		return
	}

	_ = pages.FlowTemplates.Execute(rw, map[string]any{
		"ServiceName":   h.conf.ServiceName,
		"TargetOrigin":  v.targetOrigin,
		"TargetMessage": v3,
		"AccessToken":   accessToken,
		"RefreshToken":  refreshToken,
	})
}
