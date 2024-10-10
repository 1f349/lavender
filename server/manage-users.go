package server

import (
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/pages"
	"github.com/1f349/lavender/role"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/sync/errgroup"
	"net/http"
	"net/url"
	"strconv"
)

func SetupManageUsers(r *httprouter.Router, hs *httpServer) {
	r.GET("/manage/users", hs.RequireAdminAuthentication(hs.ManageUsersGet))
	r.POST("/manage/users", hs.RequireAdminAuthentication(hs.ManageUsersPost))
}

func (h *httpServer) ManageUsersGet(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	q := req.URL.Query()
	offset, _ := strconv.Atoi(q.Get("offset"))

	var roles []string
	var userList []database.GetUserListRow
	if h.DbTx(rw, func(tx *database.Queries) (err error) {
		roles, err = tx.GetUserRoles(req.Context(), auth.Subject)
		if err != nil {
			return
		}
		userList, err = tx.GetUserList(req.Context(), int64(offset))
		return
	}) {
		return
	}
	if !HasRole(roles, role.LavenderAdmin) {
		http.Error(rw, "403 Forbidden", http.StatusForbidden)
		return
	}

	m := map[string]any{
		"ServiceName":  h.conf.ServiceName,
		"Users":        userList,
		"Offset":       offset,
		"EmailShow":    req.URL.Query().Has("show-email"),
		"CurrentAdmin": auth.Subject,
	}
	if q.Has("edit") {
		for _, i := range userList {
			if i.Subject == q.Get("edit") {
				m["EditUser"] = i
				rw.Header().Set("Content-Type", "text/html")
				rw.WriteHeader(http.StatusOK)
				pages.RenderPageTemplate(rw, "manage-users-edit", m)
				return
			}
		}
		http.Error(rw, "400 Bad Request: Invalid user to edit", http.StatusBadRequest)
		return
	}

	rw.Header().Set("Content-Type", "text/html")
	rw.WriteHeader(http.StatusOK)
	pages.RenderPageTemplate(rw, "manage-users", m)
}

func (h *httpServer) ManageUsersPost(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
	err := req.ParseForm()
	if err != nil {
		http.Error(rw, "400 Bad Request: Failed to parse form", http.StatusBadRequest)
		return
	}

	var roles []string
	if h.DbTx(rw, func(tx *database.Queries) (err error) {
		roles, err = tx.GetUserRoles(req.Context(), auth.Subject)
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
	newRoles := req.Form["roles"]
	active := req.Form.Has("active")

	switch action {
	case "edit":
		if h.DbTx(rw, func(tx *database.Queries) error {
			sub := req.Form.Get("subject")
			return tx.UseTx(req.Context(), func(tx *database.Queries) (err error) {
				err = tx.ChangeUserActive(req.Context(), database.ChangeUserActiveParams{Column1: active, Subject: sub})
				if err != nil {
					return err
				}
				err = tx.RemoveUserRoles(req.Context(), sub)
				if err != nil {
					return err
				}
				errGrp := new(errgroup.Group)
				errGrp.SetLimit(3)
				for _, roleName := range newRoles {
					errGrp.Go(func() error {
						roleId, err := strconv.ParseInt(roleName, 10, 64)
						if err != nil {
							return err
						}
						return tx.AddUserRole(req.Context(), database.AddUserRoleParams{
							RoleID:  roleId,
							Subject: sub,
						})
					})
				}
				return errGrp.Wait()
			})
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
