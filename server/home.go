package server

import (
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/pages"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"time"
)

func (h *HttpServer) Home(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	rw.Header().Set("Content-Type", "text/html")
	lNonce := uuid.NewString()
	http.SetCookie(rw, &http.Cookie{
		Name:     "lavender-nonce",
		Value:    lNonce,
		Path:     "/",
		Expires:  time.Now().Add(10 * time.Minute),
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	if auth.IsGuest() {
		pages.RenderPageTemplate(rw, "index-guest", map[string]any{
			"ServiceName": h.conf.ServiceName,
		})
		return
	}

	var isAdmin bool
	h.DbTx(rw, func(tx *database.Queries) (err error) {
		_, err = tx.UserHasRole(req.Context(), database.UserHasRoleParams{Role: "lavender:admin", Subject: auth.Subject})
		isAdmin = err == nil
		return nil
	})

	pages.RenderPageTemplate(rw, "index", map[string]any{
		"ServiceName": h.conf.ServiceName,
		"Auth":        auth,
		"Nonce":       lNonce,
		"IsAdmin":     isAdmin,
	})
}
