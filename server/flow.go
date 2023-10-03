package server

import (
	_ "embed"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

var (
	//go:embed flow-popup.go.html
	flowPopupHtml     string
	flowPopupTemplate *template.Template

	isValidState = regexp.MustCompile("^[a-z.]+%[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
)

func init() {
	pageParse, err := template.New("pages").Parse(flowPopupHtml)
	if err != nil {
		log.Fatal("flow.go: Failed to parse flow popup HTML:", err)
	}
	flowPopupTemplate = pageParse
}

func (h *HttpServer) flowPopup(rw http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	err := flowPopupTemplate.Execute(rw, map[string]any{
		"ServiceName": flowPopupTemplate,
		"Return":      req.URL.Query().Get("return"),
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

	returnUrl, err := url.Parse(req.PostFormValue("return"))
	if err != nil {
		http.Error(rw, "Invalid return URL", http.StatusBadRequest)
		return
	}
	if !login.ValidReturnUrl(returnUrl) {
		http.Error(rw, "Invalid return URL for this application", http.StatusBadRequest)
		return
	}

	// save state for use later
	state := login.Config.Namespace + "%" + uuid.NewString()
	h.flowState.Set(state, flowStateData{
		login,
		returnUrl,
	}, time.Now().Add(15*time.Minute))

	// generate oauth2 config and redirect to authorize URL
	oa2conf := login.Oauth2Config()
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
	if !isValidState.MatchString(state) {
		http.Error(rw, "Invalid state", http.StatusBadRequest)
		return
	}
	if !h.manager.CheckIssuer(state) {
		http.Error(rw, "Invalid state", http.StatusBadRequest)
		return
	}
	v, found := h.flowState.Get(state)
	if !found {
		http.Error(rw, "Invalid state", http.StatusBadRequest)
		return
	}

	// TODO: process flow callback
}
