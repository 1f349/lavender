package server

import (
	"github.com/1f349/lavender/pages"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"net/http"
)

func (h *HttpServer) Home(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	rw.Header().Set("Content-Type", "text/html")
	rw.WriteHeader(http.StatusOK)
	if auth.IsGuest() {
		pages.RenderPageTemplate(rw, "index-guest", map[string]any{
			"ServiceName": h.conf.ServiceName,
		})
		return
	}

	lNonce := uuid.NewString()
	auth.Session.Set("action-nonce", lNonce)
	if auth.Session.Save() != nil {
		http.Error(rw, "Failed to save session", http.StatusInternalServerError)
		return
	}

	pages.RenderPageTemplate(rw, "index", map[string]any{
		"ServiceName": h.conf.ServiceName,
		"Auth":        auth,
		"Subject":     auth.Data.ID,
		"DisplayName": auth.Data.DisplayName,
		"Nonce":       lNonce,
	})
}
