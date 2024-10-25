package server

import (
	auth2 "github.com/1f349/lavender/auth"
	"github.com/julienschmidt/httprouter"
	"net/http"
)

func (h *httpServer) logoutPost(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, _ auth2.UserAuth) {
	http.SetCookie(rw, &http.Cookie{
		Name:     "lavender-login-access",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(rw, &http.Cookie{
		Name:     "lavender-login-refresh",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(rw, req, "/", http.StatusFound)
}
