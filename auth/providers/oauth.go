package providers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/1f349/cache"
	"github.com/1f349/lavender/auth"
	"github.com/1f349/lavender/auth/authContext"
	"github.com/1f349/lavender/auth/process"
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/database/types"
	"github.com/1f349/lavender/issuer"
	"github.com/1f349/lavender/utils"
	"github.com/google/uuid"
	"github.com/mrmelon54/pronouns"
	"golang.org/x/oauth2"
	"golang.org/x/text/language"
	"net/http"
	"net/url"
	"time"
)

type OauthCallback interface {
	OAuthCallback(rw http.ResponseWriter, req *http.Request, namespace string, info func(req *http.Request, sso *issuer.WellKnownOIDC, token *oauth2.Token) (auth.UserAuth, error), cookie func(rw http.ResponseWriter, authData auth.UserAuth, loginName string) bool, redirect func(rw http.ResponseWriter, req *http.Request))
}

type flowStateData struct {
	loginName string
	sso       *issuer.WellKnownOIDC
	redirect  string
}

var (
	_ auth.Provider = (*OAuthLogin)(nil)
	_ auth.Button   = (*OAuthLogin)(nil)
)

type OAuthLogin struct {
	DB *database.Queries

	BaseUrl *utils.URL
	flow    *cache.Cache[string, flowStateData]
	Manager *issuer.Manager
}

func (o OAuthLogin) Init() {
	o.flow = cache.New[string, flowStateData]()
}

func (o OAuthLogin) authUrlBase(ref string) *url.URL {
	return o.BaseUrl.Resolve("oauth", o.Name(), ref).URL
}

func (o OAuthLogin) AccessState() process.State { return process.StateUnauthorized }

func (o OAuthLogin) Name() string { return "oauth" }

func (o OAuthLogin) AttemptLogin(ctx authContext.FormContext) error {
	rCtx := ctx.Context()

	login, ok := rCtx.Value(oauthServiceLogin(0)).(*issuer.WellKnownOIDC)
	if !ok {
		return fmt.Errorf("missing issuer wellknown")
	}
	loginName := rCtx.Value("login_full").(string)
	loginUn := rCtx.Value("login_username").(string)

	// save state for use later
	state := login.Config.Namespace + ":" + uuid.NewString()
	o.flow.Set(state, flowStateData{
		loginName: loginName,
		sso:       login,
		redirect:  ctx.Request().PostFormValue("redirect"),
	}, time.Now().Add(15*time.Minute))

	// generate oauth2 config and redirect to authorize URL
	oa2conf := login.OAuth2Config
	oa2conf.RedirectURL = o.authUrlBase("callback").String()
	nextUrl := oa2conf.AuthCodeURL(state, oauth2.SetAuthURLParam("login_name", loginUn))

	return auth.RedirectError{Target: nextUrl, Code: http.StatusFound}
}

func (o OAuthLogin) OAuthCallback(rw http.ResponseWriter, req *http.Request, namespace string, info func(req *http.Request, sso *issuer.WellKnownOIDC, token *oauth2.Token) (auth.UserAuth, error), cookie func(rw http.ResponseWriter, authData auth.UserAuth, loginName string) bool, redirect func(rw http.ResponseWriter, req *http.Request)) {
	flowState, ok := o.flow.Get(req.FormValue("state"))
	if !ok {
		http.Error(rw, "Invalid flow state", http.StatusBadRequest)
		return
	}
	if flowState.sso.Namespace != namespace {
		http.Error(rw, "OAuth source mismatch", http.StatusBadRequest)
		return
	}
	token, err := flowState.sso.OAuth2Config.Exchange(context.Background(), req.FormValue("code"), oauth2.SetAuthURLParam("redirect_uri", o.authUrlBase("callback").String()))
	if err != nil {
		http.Error(rw, "Failed to exchange code for token", http.StatusInternalServerError)
		return
	}

	userAuth, err := info(req, flowState.sso, token)
	if err != nil {
		http.Error(rw, "Failed to update external user info", http.StatusInternalServerError)
		return
	}

	if cookie(rw, userAuth, flowState.loginName) {
		http.Error(rw, "Failed to save login cookie", http.StatusInternalServerError)
		return
	}
	if flowState.redirect != "" {
		req.Form.Set("redirect", flowState.redirect)
	}
	redirect(rw, req)
}

func (o OAuthLogin) RenderButtonTemplate(ctx authContext.TemplateContext) {
	// TODO: idk what this is
	// o.authUrlBase("button")
	// provide something non-nil
	ctx.Render(struct {
		Href       string
		ButtonName string
	}{
		Href:       o.authUrlBase("start").String(),
		ButtonName: "Login with Unknown OAuth Button", // TODO: actually get the service name
	})
}

// RedirectToAuthorize returns true when redirecting to the authorize endpoint
// for the requested namespace.
func (o OAuthLogin) RedirectToAuthorize(rw http.ResponseWriter, req *http.Request, namespace string) bool {
	oidc := o.Manager.GetService(namespace)
	if oidc == nil {
		return false
	}

	// TODO: come back to fix this
	oidc.OAuth2Config.AuthCodeURL("state")
	//	http.Redirect(rw, req, oidc.AuthorizationEndpoint, http.StatusOK)
	return true
}

type oauthServiceLogin int

func WithWellKnown(ctx context.Context, login *issuer.WellKnownOIDC) context.Context {
	return context.WithValue(ctx, oauthServiceLogin(0), login)
}

func (o OAuthLogin) updateExternalUserInfo(req *http.Request, sso *issuer.WellKnownOIDC, token *oauth2.Token) (auth.UserAuth, error) {
	sessionData, err := o.fetchUserInfo(sso, token)
	if err != nil || sessionData.Subject == "" {
		return auth.UserAuth{}, fmt.Errorf("failed to fetch user info")
	}

	// TODO(melon): fix this to use a merging of lavender and tulip auth

	// find an existing user with the matching oauth2 namespace and subject
	var userSubject string
	err = o.DB.UseTx(req.Context(), func(tx *database.Queries) (err error) {
		userSubject, err = tx.FindUserByAuth(req.Context(), database.FindUserByAuthParams{
			AuthType:      types.AuthTypeOauth2,
			AuthNamespace: sso.Namespace,
			AuthUser:      sessionData.Subject,
		})
		return
	})
	switch {
	case err == nil:
		// user already exists
		err = o.DB.UseTx(req.Context(), func(tx *database.Queries) (err error) {
			return o.updateOAuth2UserProfile(req.Context(), tx, sessionData)
		})
		return auth.UserAuth{
			Subject:  userSubject,
			Factor:   process.StateBasic, // TODO: should the user be allowed to skip otp via oauth?
			UserInfo: sessionData.UserInfo,
		}, err
	case errors.Is(err, sql.ErrNoRows):
		// happy path for registration
		break
	default:
		// another error occurred
		return auth.UserAuth{}, err
	}

	// guard for disabled registration
	if !sso.Config.Registration {
		return auth.UserAuth{}, fmt.Errorf("registration is not enabled for this authentication source")
	}

	// TODO(melon): rework this
	name := sessionData.UserInfo.GetStringOrDefault("name", "Unknown User")
	uEmail := sessionData.UserInfo.GetStringOrDefault("email", "unknown@localhost")
	uEmailVerified, _ := sessionData.UserInfo.GetBoolean("email_verified")

	err = o.DB.UseTx(req.Context(), func(tx *database.Queries) (err error) {
		userSubject, err = tx.AddOAuthUser(req.Context(), database.AddOAuthUserParams{
			Email:         uEmail,
			EmailVerified: uEmailVerified,
			Name:          name,
			Username:      sessionData.UserInfo.GetStringFromKeysOrEmpty("login", "preferred_username"),
			AuthNamespace: sso.Namespace,
			AuthUser:      sessionData.UserInfo.GetStringOrEmpty("sub"),
		})
		if err != nil {
			return err
		}

		// if adding the user succeeds then update the profile
		return o.updateOAuth2UserProfile(req.Context(), tx, sessionData)
	})
	if err != nil {
		return auth.UserAuth{}, err
	}

	// only continues if the above tx succeeds
	if err := o.DB.UseTx(req.Context(), func(tx *database.Queries) error {
		return tx.UpdateUserToken(req.Context(), database.UpdateUserTokenParams{
			AccessToken:  sql.NullString{String: token.AccessToken, Valid: true},
			RefreshToken: sql.NullString{String: token.RefreshToken, Valid: true},
			TokenExpiry:  sql.NullTime{Time: token.Expiry, Valid: true},
			Subject:      sessionData.Subject,
		})
	}); err != nil {
		return auth.UserAuth{}, err
	}

	// TODO(melon): this feels bad
	sessionData = auth.UserAuth{
		Subject:  userSubject,
		Factor:   process.StateAuthenticated, // TODO: should the user be allowed to skip otp via oauth?
		UserInfo: sessionData.UserInfo,
	}

	return sessionData, nil
}

func (o OAuthLogin) updateOAuth2UserProfile(ctx context.Context, tx *database.Queries, sessionData auth.UserAuth) error {
	// all of these updates must succeed
	return tx.UseTx(ctx, func(tx *database.Queries) error {
		name := sessionData.UserInfo.GetStringOrDefault("name", "Unknown User")

		err := tx.ModifyUserRemoteLogin(ctx, database.ModifyUserRemoteLoginParams{
			Login:      sessionData.UserInfo.GetStringFromKeysOrEmpty("login", "preferred_username"),
			ProfileUrl: sessionData.UserInfo.GetStringOrEmpty("profile"),
			Subject:    sessionData.Subject,
		})
		if err != nil {
			return err
		}

		pronoun, err := pronouns.FindPronoun(sessionData.UserInfo.GetStringOrEmpty("pronouns"))
		if err != nil {
			pronoun = pronouns.TheyThem
		}
		locale, err := language.Parse(sessionData.UserInfo.GetStringOrEmpty("locale"))
		if err != nil {
			locale = language.AmericanEnglish
		}

		return tx.ModifyProfile(ctx, database.ModifyProfileParams{
			Name:      name,
			Picture:   sessionData.UserInfo.GetStringOrEmpty("profile"),
			Website:   sessionData.UserInfo.GetStringOrEmpty("website"),
			Pronouns:  types.UserPronoun{Pronoun: pronoun},
			Birthdate: sessionData.UserInfo.GetNullDate("birthdate"),
			Zone:      sessionData.UserInfo.GetStringOrDefault("zoneinfo", "UTC"),
			Locale:    types.UserLocale{Tag: locale},
			UpdatedAt: time.Now(),
			Subject:   sessionData.Subject,
		})
	})
}

func (o OAuthLogin) fetchUserInfo(sso *issuer.WellKnownOIDC, token *oauth2.Token) (auth.UserAuth, error) {
	res, err := sso.OAuth2Config.Client(context.Background(), token).Get(sso.UserInfoEndpoint.String())
	if err != nil || res.StatusCode != http.StatusOK {
		return auth.UserAuth{}, fmt.Errorf("request failed")
	}
	defer res.Body.Close()

	var userInfoJson auth.UserInfoFields
	if err := json.NewDecoder(res.Body).Decode(&userInfoJson); err != nil {
		return auth.UserAuth{}, err
	}
	subject, ok := userInfoJson.GetString("sub")
	if !ok {
		return auth.UserAuth{}, fmt.Errorf("invalid subject")
	}

	// TODO(melon): there is no need for this
	//subject += "@" + sso.Config.Namespace

	return auth.UserAuth{
		Subject:  subject,
		Factor:   process.StateBasic, // TODO: should the user be allowed to skip otp via oauth?
		UserInfo: userInfoJson,
	}, nil
}
