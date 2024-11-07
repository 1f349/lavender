package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"github.com/1f349/mjwt"
	"github.com/1f349/mjwt/auth"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"strings"
)

type JWTAccessGenerate struct {
	signer *mjwt.Issuer
	db     mjwtGetUserRoles
}

func NewMJWTAccessGenerate(signer *mjwt.Issuer, db mjwtGetUserRoles) *JWTAccessGenerate {
	return &JWTAccessGenerate{signer, db}
}

var _ oauth2.AccessGenerate = &JWTAccessGenerate{}

type mjwtGetUserRoles interface {
	GetUserRoles(ctx context.Context, subject string) ([]string, error)
}

func (j *JWTAccessGenerate) Token(ctx context.Context, data *oauth2.GenerateBasic, isGenRefresh bool) (access, refresh string, err error) {
	roles, err := j.db.GetUserRoles(ctx, data.UserID)
	if err != nil {
		return "", "", err
	}

	ps := auth.NewPermStorage()
	for _, role := range roles {
		ps.Set(role)
	}
	out := auth.NewPermStorage()
	ForEachRole(data.Client.(interface{ UsePerms() []string }).UsePerms(), func(role string) {
		for _, i := range ps.Filter(strings.Split(role, " ")).Dump() {
			out.Set(i)
		}
	})

	access, err = j.signer.GenerateJwt(data.UserID, "", jwt.ClaimStrings{data.TokenInfo.GetClientID()}, data.TokenInfo.GetAccessExpiresIn(), auth.AccessTokenClaims{
		Perms: out,
	})

	if isGenRefresh {
		t := uuid.NewHash(sha256.New(), uuid.New(), []byte(access), 5).String()
		refresh = base64.URLEncoding.EncodeToString([]byte(t))
		refresh = strings.ToUpper(strings.TrimRight(refresh, "="))
	}

	return
}
