package server

import (
	_ "embed"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"
)

var (
	//go:embed flow-popup.go.html
	flowPopupHtml     string
	flowPopupTemplate *template.Template

	//go:embed flow-callback.go.html
	flowCallbackHtml     string
	flowCallbackTemplate *template.Template
)

func init() {
	pageParse, err := template.New("pages").Parse(flowPopupHtml)
	if err != nil {
		log.Fatal("flow.go: Failed to parse flow popup HTML:", err)
	}
	flowPopupTemplate = pageParse
	pageParse, err = template.New("pages").Parse(flowCallbackHtml)
	if err != nil {
		log.Fatal("flow.go: Failed to parse flow callback HTML:", err)
	}
	flowCallbackTemplate = pageParse
}

func (h *HttpServer) flowPopup(rw http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	err := flowPopupTemplate.Execute(rw, map[string]any{
		"ServiceName": flowPopupTemplate,
		"Origin":      req.URL.Query().Get("origin"),
	})
	if err != nil {
		log.Printf("Failed to render page: %s\n", err)
	}
}

func (h *HttpServer) flowPopupPost(rw http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	login := h.manager.FindServiceFromLogin(req.PostFormValue("username"))
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
	state := login.Config.Namespace + "%" + uuid.NewString()
	h.flowState.Set(state, flowStateData{
		login,
		targetOrigin,
	}, time.Now().Add(15*time.Minute))

	// generate oauth2 config and redirect to authorize URL
	oa2conf := login.OAuth2Config
	oa2conf.RedirectURL = h.baseUrl + "/callback"
	nextUrl := oa2conf.AuthCodeURL(state)
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
	n := strings.IndexByte(state, '%')
	if !h.manager.CheckNamespace(state[:n]) {
		http.Error(rw, "Invalid state", http.StatusBadRequest)
		return
	}
	v, found := h.flowState.Get(state)
	if !found {
		http.Error(rw, "Invalid state", http.StatusBadRequest)
		return
	}

	exchange, err := v.sso.OAuth2Config.Exchange(req.Context(), q.Get("code"))
	if err != nil {
		http.Error(rw, "Failed to exchange code", http.StatusInternalServerError)
		return
	}
	client := v.sso.OAuth2Config.Client(req.Context(), exchange)
	v2, err := client.Get(v.sso.UserInfoEndpoint)
	if err != nil {
		http.Error(rw, "Failed to get userinfo", http.StatusInternalServerError)
		return
	}
	defer v2.Body.Close()
	if v2.StatusCode != http.StatusOK {
		http.Error(rw, "Failed to get userinfo", http.StatusInternalServerError)
		return
	}
	var v3 any
	if json.NewDecoder(v2.Body).Decode(&v3) != nil {
		http.Error(rw, "Failed to decode userinfo JSON", http.StatusInternalServerError)
		return
	}

	_ = flowCallbackTemplate.Execute(rw, map[string]any{
		"TargetOrigin":  v.targetOrigin,
		"TargetMessage": v3,
	})
}
