package server

import (
	"database/sql"
	"errors"
	"github.com/1f349/lavender/auth"
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/role"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"net/url"
	"strings"
)

type UserHandler func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, auth UserAuth)

type UserAuth struct {
	Subject  string
	Factor   auth.Factor
	UserInfo auth.UserInfoFields
}

func (u UserAuth) IsGuest() bool { return u.Subject == "" }

func (u UserAuth) NextFlowUrl(origin *url.URL) *url.URL {
	if u.Factor < auth.FactorAuthorized {
		return PrepareRedirectUrl("/login", origin)
	}
	return nil
}

var ErrAuthHttpError = errors.New("auth http error")

func (h *httpServer) RequireAdminAuthentication(next UserHandler) httprouter.Handle {
	return h.RequireAuthentication(func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, auth UserAuth) {
		var hasRole bool
		if h.DbTx(rw, func(tx *database.Queries) (err error) {
			err = tx.UserHasRole(req.Context(), database.UserHasRoleParams{
				Role:    role.LavenderAdmin,
				Subject: auth.Subject,
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
		next(rw, req, params, auth)
	})
}

func (h *httpServer) RequireAuthentication(next UserHandler) httprouter.Handle {
	return h.OptionalAuthentication(false, func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, auth UserAuth) {
		if auth.IsGuest() {
			redirectUrl := PrepareRedirectUrl("/login", req.URL)
			http.Redirect(rw, req, redirectUrl.String(), http.StatusFound)
			return
		}
		next(rw, req, params, auth)
	})
}

func (h *httpServer) OptionalAuthentication(flowPart bool, next UserHandler) httprouter.Handle {
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

func (h *httpServer) internalAuthenticationHandler(rw http.ResponseWriter, req *http.Request) (UserAuth, error) {
	// Delete previous login data cookie
	http.SetCookie(rw, &http.Cookie{
		Name:     "lavender-login-data",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	var u UserAuth
	err := h.readLoginAccessCookie(rw, req, &u)
	if err != nil {
		// not logged in
		return UserAuth{}, nil
	}
	return u, nil
}

func PrepareRedirectUrl(targetPath string, origin *url.URL) *url.URL {
	// find start of query parameters in target path
	n := strings.IndexByte(targetPath, '?')
	v := url.Values{}

	// parse existing query parameters
	if n != -1 {
		q, err := url.ParseQuery(targetPath[n+1:])
		if err != nil {
			panic("PrepareRedirectUrl: invalid hardcoded target path query parameters")
		}
		v = q
		targetPath = targetPath[:n]
	}

	// add path of origin as a new query parameter
	orig := origin.Path
	if origin.RawQuery != "" || origin.ForceQuery {
		orig += "?" + origin.RawQuery
	}
	if orig != "" {
		v.Set("redirect", orig)
	}
	return &url.URL{Path: targetPath, RawQuery: v.Encode()}
}
