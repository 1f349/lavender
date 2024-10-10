package server

import (
	"bytes"
	"encoding/json"
	"github.com/1f349/lavender/logger"
	"github.com/1f349/lavender/openid"
	"github.com/1f349/mjwt"
	"github.com/julienschmidt/httprouter"
	"net/http"
)

func SetupOpenId(r *httprouter.Router, baseUrl string, signingKey *mjwt.Issuer) {
	openIdConf := openid.GenConfig(baseUrl, []string{
		"openid", "name", "username", "profile", "email", "birthdate", "age", "zoneinfo", "locale",
	}, []string{
		"sub", "name", "preferred_username", "profile", "picture", "website", "email", "email_verified", "gender", "birthdate", "zoneinfo", "locale", "updated_at",
	})
	openIdBytes, err := json.Marshal(openIdConf)
	if err != nil {
		logger.Logger.Fatal("Failed to generate OpenID configuration", "err", err)
	}

	jwkSetBuffer := new(bytes.Buffer)
	err = mjwt.WriteJwkSetJson(jwkSetBuffer, []*mjwt.Issuer{signingKey})
	if err != nil {
		logger.Logger.Fatal("Failed to generate JWK Set", "err", err)
	}

	r.GET("/.well-known/openid-configuration", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write(openIdBytes)
	})
	r.GET("/.well-known/jwks.json", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write(jwkSetBuffer.Bytes())
	})
}
