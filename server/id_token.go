package server

import (
	"github.com/1f349/lavender/database"
	"github.com/1f349/mjwt"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/golang-jwt/jwt/v4"
	"strings"
)

func addIdTokenSupport(srv *server.Server, db *database.DB, key mjwt.Signer) {
	srv.SetExtensionFieldsHandler(func(ti oauth2.TokenInfo) (fieldsValue map[string]interface{}) {
		scope := ti.GetScope()
		if containsScope(scope, "openid") {
			idToken, err := generateIDToken(ti, db, key)
			if err != nil {
				return
			}
			fieldsValue = map[string]interface{}{}
			fieldsValue["id_token"] = idToken
		}
		return
	})
}

// IdTokenClaims contains the JWT claims for an access token
type IdTokenClaims struct {
	Subject string `json:"subject"`
}

func (a IdTokenClaims) Valid() error { return nil }
func (a IdTokenClaims) Type() string { return "id-token" }

func generateIDToken(ti oauth2.TokenInfo, us *database.DB, key mjwt.Signer) (token string, err error) {
	tx, err := us.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	user, err := tx.GetUser(ti.GetUserID())
	if err != nil {
		return "", err
	}

	token, err = key.GenerateJwt(user.Subject, "", jwt.ClaimStrings{ti.GetClientID()}, ti.GetAccessExpiresIn(), &IdTokenClaims{Subject: user.Subject})
	return
}

func containsScope(scopes, s string) bool {
	_scopes := strings.Split(scopes, " ")
	for _, _s := range _scopes {
		if _s == s {
			return true
		}
	}
	return false
}
