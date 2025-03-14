package providers

import (
	"errors"
	"fmt"
	"github.com/1f349/lavender/auth"
	"github.com/1f349/lavender/auth/authContext"
	"github.com/1f349/lavender/auth/process"
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/issuer"
	"github.com/1f349/lavender/logger"
	"github.com/1f349/lavender/utils"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"net/http"
	"strings"
	"time"
)

const memoryCookieName = "lavender-user-memory"

var _ auth.Provider = (*Base)(nil)
var _ auth.Form = (*Base)(nil)

type Base struct {
	DB          *database.Queries
	MyNamespace string
	Manager     *issuer.Manager
	OAuth       *OAuthLogin
}

func (b *Base) AccessState() process.State { return process.StateUnauthorized }

func (b *Base) Name() string { return "base" }

func (b *Base) String() string { return "%Provider(base)" }

func (b *Base) RenderTemplate(ctx authContext.TemplateContext) error {
	type s struct {
		LoginNameMemory bool
		UserEmail       string
		Redirect        string
	}

	req := ctx.Request()
	q := req.URL.Query()

	userEmail := ctx.LoginProcessData().Email
	if userEmail == "" {
		cookie, err := req.Cookie(memoryCookieName)
		if err == nil && cookie.Valid() == nil {
			userEmail = cookie.Value
		}
	}

	ctx.Render(s{
		UserEmail: userEmail,
		Redirect:  q.Get("redirect"),
	})
	return nil
}

func (b *Base) AttemptLogin(ctx authContext.FormContext) error {
	req := ctx.Request()
	rw := ctx.ResponseWriter()

	if req.FormValue("not-you") != "" {
		http.SetCookie(rw, &http.Cookie{
			Name:     memoryCookieName,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		return auth.RedirectError{
			Target: "/login",
			Code:   http.StatusFound,
		}
	}

	loginName := req.FormValue("email")
	if loginName == "" {
		return errors.New("email required")
	}

	rememberMe := req.FormValue("remember-me") != ""
	logger.Logger.Debug("Hi", "login", loginName, "remember", rememberMe)

	// Set the remember me cookie
	if rememberMe {
		now := time.Now()
		future := now.AddDate(1, 0, 0)
		http.SetCookie(rw, &http.Cookie{
			Name:     memoryCookieName,
			Value:    loginName,
			Path:     "/",
			Expires:  future,
			MaxAge:   int(future.Sub(now).Seconds()),
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
	}

	// append local namespace if @ is missing
	if !strings.ContainsRune(loginName, '@') {
		loginName += "@" + b.MyNamespace
	}

	user, namespace, err := utils.ParseLoginName(loginName)
	if err != nil {
		http.Error(rw, "Invalid login name", http.StatusBadRequest)
		return fmt.Errorf("invalid login name %s", loginName)
	}

	login := b.Manager.GetService(namespace)
	if login == nil {
		http.Error(rw, "No login service defined for this username", http.StatusBadRequest)
		return errors.New("no login service defined for this username")
	}

	// the login is not for this namespace
	if login != issuer.MeWellKnown {
		// TODO: this is oauth request code start oauth request
		// TODO: this could all be 1 function call into oauth

		// save state for use later
		state := login.Config.Namespace + ":" + uuid.NewString()
		b.OAuth.flow.Set(state, flowStateData{loginName, login, req.PostFormValue("redirect")}, time.Now().Add(15*time.Minute))

		// generate oauth2 config and redirect to authorize URL
		oa2conf := login.OAuth2Config
		oa2conf.RedirectURL = b.OAuth.BaseUrl.JoinPath("callback").String()
		nextUrl := oa2conf.AuthCodeURL(state, oauth2.SetAuthURLParam("login_name", user))
		return auth.RedirectError{
			Target: nextUrl,
			Code:   http.StatusFound,
		}
	}

	ctx.UpdateSession(process.LoginProcessData{
		Email: loginName,
		State: process.StateBase,
	})

	return nil
}
