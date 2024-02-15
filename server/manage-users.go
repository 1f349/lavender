package server

import (
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/pages"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"net/url"
	"strconv"
)

func (h *HttpServer) ManageUsersGet(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	offset := 0
	q := req.URL.Query()
	if q.Has("offset") {
		var err error
		offset, err = strconv.Atoi(q.Get("offset"))
		if err != nil {
			http.Error(rw, "400 Bad Request: Invalid offset", http.StatusBadRequest)
			return
		}
	}

	var roles string
	var userList []database.User
	if h.DbTx(rw, func(tx *database.Tx) (err error) {
		roles, err = tx.GetUserRoles(auth.ID)
		if err != nil {
			return
		}
		userList, err = tx.GetUserList(offset)
		return
	}) {
		return
	}
	if !HasRole(roles, "lavender:admin") {
		http.Error(rw, "403 Forbidden", http.StatusForbidden)
		return
	}

	m := map[string]any{
		"ServiceName":  h.conf.ServiceName,
		"Users":        userList,
		"Offset":       offset,
		"EmailShow":    req.URL.Query().Has("show-email"),
		"CurrentAdmin": auth.ID,
	}
	if q.Has("edit") {
		for _, i := range userList {
			if i.Sub == q.Get("edit") {
				m["Edit"] = i
				goto validEdit
			}
		}
		http.Error(rw, "400 Bad Request: Invalid user to edit", http.StatusBadRequest)
		return
	}

validEdit:
	rw.Header().Set("Content-Type", "text/html")
	rw.WriteHeader(http.StatusOK)
	pages.RenderPageTemplate(rw, "manage-users", m)
}

func (h *HttpServer) ManageUsersPost(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	err := req.ParseForm()
	if err != nil {
		http.Error(rw, "400 Bad Request: Failed to parse form", http.StatusBadRequest)
		return
	}

	var roles string
	if h.DbTx(rw, func(tx *database.Tx) (err error) {
		roles, err = tx.GetUserRoles(auth.ID)
		return
	}) {
		return
	}
	if !HasRole(roles, "lavender:admin") {
		http.Error(rw, "400 Bad Request: Only admin users can manage users", http.StatusBadRequest)
		return
	}

	offset := req.Form.Get("offset")
	action := req.Form.Get("action")
	newRoles := req.Form.Get("roles")
	active := req.Form.Has("active")

	switch action {
	case "edit":
		if h.DbTx(rw, func(tx *database.Tx) error {
			sub := req.Form.Get("subject")
			return tx.UpdateUser(sub, newRoles, active)
		}) {
			return
		}
	default:
		http.Error(rw, "400 Bad Request: Invalid action", http.StatusBadRequest)
		return
	}

	redirectUrl := url.URL{Path: "/manage/users", RawQuery: url.Values{"offset": []string{offset}}.Encode()}
	http.Redirect(rw, req, redirectUrl.String(), http.StatusFound)
}
