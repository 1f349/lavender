package auth

import (
	"context"
	"fmt"
	"github.com/1f349/cache"
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/issuer"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"net/http"
	"time"
)

type flowStateData struct {
	loginName string
	sso       *issuer.WellKnownOIDC
	redirect  string
}

var _ Provider = (*OAuthLogin)(nil)

type OAuthLogin struct {
	DB *database.Queries

	BaseUrl string

	flow *cache.Cache[string, flowStateData]
}

func (o OAuthLogin) Init() {
	o.flow = cache.New[string, flowStateData]()
}

func (o OAuthLogin) Factor() Factor { return FactorFirst }

func (o OAuthLogin) Name() string { return "oauth" }

func (o OAuthLogin) RenderData(ctx context.Context, req *http.Request, user *database.User, data map[string]any) error {
	//TODO implement me
	panic("implement me")
}

func (o OAuthLogin) AttemptLogin(ctx context.Context, req *http.Request, user *database.User) error {
	login, ok := ctx.Value(oauthServiceLogin(0)).(*issuer.WellKnownOIDC)
	if !ok {
		return fmt.Errorf("missing issuer wellknown")
	}
	loginName := ctx.Value("login_full").(string)
	loginUn := ctx.Value("login_username").(string)

	// save state for use later
	state := login.Config.Namespace + ":" + uuid.NewString()
	o.flow.Set(state, flowStateData{loginName, login, req.PostFormValue("redirect")}, time.Now().Add(15*time.Minute))

	// generate oauth2 config and redirect to authorize URL
	oa2conf := login.OAuth2Config
	oa2conf.RedirectURL = o.BaseUrl + "/callback"
	nextUrl := oa2conf.AuthCodeURL(state, oauth2.SetAuthURLParam("login_name", loginUn))

	return RedirectError{Target: nextUrl, Code: http.StatusFound}
}

func (o OAuthLogin) OAuthCallback(rw http.ResponseWriter, req *http.Request, info func(req *http.Request, sso *issuer.WellKnownOIDC, token *oauth2.Token) (UserAuth, error), cookie func(rw http.ResponseWriter, authData UserAuth, loginName string) bool, redirect func(rw http.ResponseWriter, req *http.Request)) {
	flowState, ok := o.flow.Get(req.FormValue("state"))
	if !ok {
		http.Error(rw, "Invalid flow state", http.StatusBadRequest)
		return
	}
	token, err := flowState.sso.OAuth2Config.Exchange(context.Background(), req.FormValue("code"), oauth2.SetAuthURLParam("redirect_uri", o.BaseUrl+"/callback"))
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

type oauthServiceLogin int

func WithWellKnown(ctx context.Context, login *issuer.WellKnownOIDC) context.Context {
	return context.WithValue(ctx, oauthServiceLogin(0), login)
}
