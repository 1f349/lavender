package server

import (
	_ "embed"
	"github.com/julienschmidt/httprouter"
	"html/template"
	"log"
	"net/http"
)

var (
	//go:embed flow-popup.go.html
	flowPopupHtml     string
	flowPopupTemplate *template.Template
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

func (h *HttpServer) flowPopupPost(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
	login := h.manager.FindServiceFromLogin(req.PostFormValue("username"))
	if login == nil {
		http.Error(rw, "No login service defined for this username", http.StatusBadRequest)
		return
	}

	login.AuthorizationEndpoint

	// https://github.com/go-oauth2/oauth2/blob/master/example/client/client.go
}

func (h *HttpServer) flowCallback(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {

}
