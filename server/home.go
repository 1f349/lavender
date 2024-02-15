package server

import (
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/pages"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"time"
)

func (h *HttpServer) Home(rw http.ResponseWriter, _ *http.Request, _ httprouter.Params, auth UserAuth) {
	rw.Header().Set("Content-Type", "text/html")
	lNonce := uuid.NewString()
	http.SetCookie(rw, &http.Cookie{
		Name:     "tulip-nonce",
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
	h.DbTx(rw, func(tx *database.Tx) (err error) {
		roles, err := tx.GetUserRoles(auth.ID)
		isAdmin = HasRole(roles, "lavender:admin")
		return err
	})

	pages.RenderPageTemplate(rw, "index", map[string]any{
		"ServiceName": h.conf.ServiceName,
		"Auth":        auth,
		"Subject":     auth.ID,
		"DisplayName": auth.DisplayName,
		"Nonce":       lNonce,
		"IsAdmin":     isAdmin,
	})
}
