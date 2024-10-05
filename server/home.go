package server

import (
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/pages"
	"github.com/1f349/lavender/role"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"time"
)

func (h *httpServer) Home(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth UserAuth) {
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
		err = tx.UserHasRole(req.Context(), database.UserHasRoleParams{Role: role.LavenderAdmin, Subject: auth.Subject})
		isAdmin = err == nil
		return nil
	})

	pages.RenderPageTemplate(rw, "index", map[string]any{
		"ServiceName": h.conf.ServiceName,
		"Auth":        auth,
		"Nonce":       lNonce,
		"IsAdmin":     isAdmin,
	})

	//	rw.Header().Set("Content-Type", "text/html")
	//	lNonce := uuid.NewString()
	//	http.SetCookie(rw, &http.Cookie{
	//		Name:     "tulip-nonce",
	//		Value:    lNonce,
	//		Path:     "/",
	//		Expires:  time.Now().Add(10 * time.Minute),
	//		Secure:   true,
	//		SameSite: http.SameSiteLaxMode,
	//	})
	//
	//	if auth.IsGuest() {
	//		pages.RenderPageTemplate(rw, "index-guest", map[string]any{
	//			"ServiceName": h.conf.ServiceName,
	//		})
	//		return
	//	}
	//
	//	var userWithName string
	//	var userRole types.UserRole
	//	var hasTwoFactor bool
	//	if h.DbTx(rw, func(tx *database.Queries) (err error) {
	//		userWithName, err = tx.GetUserDisplayName(req.Context(), auth.Subject)
	//		if err != nil {
	//			return fmt.Errorf("failed to get user display name: %w", err)
	//		}
	//		hasTwoFactor, err = tx.HasOtp(req.Context(), auth.Subject)
	//		if err != nil {
	//			return fmt.Errorf("failed to get user two factor state: %w", err)
	//		}
	//		userRole, err = tx.GetUserRole(req.Context(), auth.Subject)
	//		if err != nil {
	//			return fmt.Errorf("failed to get user role: %w", err)
	//		}
	//		return
	//	}) {
	//		return
	//	}
	//	pages.RenderPageTemplate(rw, "index", map[string]any{
	//		"ServiceName": h.conf.ServiceName,
	//		"Auth":        auth,
	//		"User":        database.User{Subject: auth.Subject, Name: userWithName, Role: userRole},
	//		"Nonce":       lNonce,
	//		"OtpEnabled":  hasTwoFactor,
	//		"IsAdmin":     userRole == types.RoleAdmin,
	//	})
}
