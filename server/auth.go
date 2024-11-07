package server

import (
	"database/sql"
	"errors"
	"github.com/1f349/lavender/auth"
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/role"
	"github.com/julienschmidt/httprouter"
	"net/http"
)

var ErrAuthHttpError = errors.New("auth http error")

func (h *httpServer) RequireAdminAuthentication(next auth.UserHandler) httprouter.Handle {
	return h.RequireAuthentication(func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, userAuth auth.UserAuth) {
		var hasRole bool
		if h.DbTx(rw, func(tx *database.Queries) (err error) {
			err = tx.UserHasRole(req.Context(), database.UserHasRoleParams{
				Role:    role.LavenderAdmin,
				Subject: userAuth.Subject,
			})
			switch {
			case err == nil:
				hasRole = true
			case errors.Is(err, sql.ErrNoRows):
				hasRole = false
				err = nil
			}
			return
		}) {
			return
		}
		if !hasRole {
			http.Error(rw, "403 Forbidden", http.StatusForbidden)
			return
		}
		next(rw, req, params, userAuth)
	})
}

func (h *httpServer) RequireAuthentication(next auth.UserHandler) httprouter.Handle {
	return h.OptionalAuthentication(false, func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, userAuth auth.UserAuth) {
		if userAuth.IsGuest() {
			redirectUrl := auth.PrepareRedirectUrl("/login", req.URL)
			http.Redirect(rw, req, redirectUrl.String(), http.StatusFound)
			return
		}
		next(rw, req, params, userAuth)
	})
}

func (h *httpServer) OptionalAuthentication(flowPart bool, next auth.UserHandler) httprouter.Handle {
	return func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		authData, err := h.internalAuthenticationHandler(rw, req)
		if err != nil {
			if !errors.Is(err, ErrAuthHttpError) {
				http.Error(rw, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		if n := authData.NextFlowUrl(req.URL); n != nil && !flowPart {
			http.Redirect(rw, req, n.String(), http.StatusFound)
			return
		}
		next(rw, req, params, authData)
	}
}

func (h *httpServer) internalAuthenticationHandler(rw http.ResponseWriter, req *http.Request) (auth.UserAuth, error) {
	// Delete previous login data cookie
	http.SetCookie(rw, &http.Cookie{
		Name:     "lavender-login-data",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	var u auth.UserAuth
	err := h.readLoginAccessCookie(rw, req, &u)
	if err != nil {
		// not logged in
		return auth.UserAuth{}, nil
	}
	return u, nil
}
