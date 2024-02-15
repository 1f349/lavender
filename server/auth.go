package server

import (
	"github.com/1f349/lavender/database"
	"github.com/1f349/mjwt"
	"github.com/1f349/mjwt/auth"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"net/url"
	"strings"
)

type UserHandler func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, auth UserAuth)

type UserAuth struct {
	ID          string
	DisplayName string
	UserInfo    UserInfoFields
}

func (u UserAuth) IsGuest() bool { return u.ID == "" }

func (h *HttpServer) RequireAdminAuthentication(next UserHandler) httprouter.Handle {
	return h.RequireAuthentication(func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, auth UserAuth) {
		var roles string
		if h.DbTx(rw, func(tx *database.Tx) (err error) {
			roles, err = tx.GetUserRoles(auth.ID)
			return
		}) {
			return
		}
		if !HasRole(roles, "lavender:admin") {
			http.Error(rw, "403 Forbidden", http.StatusForbidden)
			return
		}
		next(rw, req, params, auth)
	})
}

func (h *HttpServer) RequireAuthentication(next UserHandler) httprouter.Handle {
	return h.OptionalAuthentication(func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, auth UserAuth) {
		if auth.IsGuest() {
			redirectUrl := PrepareRedirectUrl("/login", req.URL)
			http.Redirect(rw, req, redirectUrl.String(), http.StatusFound)
			return
		}
		next(rw, req, params, auth)
	})
}

func (h *HttpServer) OptionalAuthentication(next UserHandler) httprouter.Handle {
	return func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		auth, err := h.internalAuthenticationHandler(req)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		if auth.IsGuest() {
			// if this fails internally it just sees the user as logged out
			h.readLoginDataCookie(req, &auth)
		}
		next(rw, req, params, auth)
	}
}

func (h *HttpServer) internalAuthenticationHandler(req *http.Request) (UserAuth, error) {
	if loginCookie, err := req.Cookie("tulip-login-data"); err == nil {
		_, b, err := mjwt.ExtractClaims[auth.AccessTokenClaims](h.signingKey, loginCookie.Value)
		if err != nil {
			return UserAuth{}, err
		}
		return UserAuth{ID: b.Subject}, nil
	}
	// not logged in
	return UserAuth{}, nil
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
