package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"github.com/1f349/lavender/database"
	"github.com/1f349/mjwt"
	"github.com/1f349/mjwt/auth"
	"github.com/1f349/mjwt/claims"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"strings"
)

type JWTAccessGenerate struct {
	signer mjwt.Signer
	db     *database.DB
}

func NewJWTAccessGenerate(signer mjwt.Signer, db *database.DB) *JWTAccessGenerate {
	return &JWTAccessGenerate{signer, db}
}

var _ oauth2.AccessGenerate = &JWTAccessGenerate{}

func (j *JWTAccessGenerate) Token(ctx context.Context, data *oauth2.GenerateBasic, isGenRefresh bool) (access, refresh string, err error) {
	beginCtx, err := j.db.BeginCtx(ctx)
	if err != nil {
		return "", "", err
	}
	roles, err := beginCtx.GetUserRoles(data.UserID)
	if err != nil {
		return "", "", err
	}
	beginCtx.Rollback()

	ps := claims.NewPermStorage()
	ForEachRole(data.Client.(interface{ UsePerms() string }).UsePerms(), func(role string) {
		if HasRole(roles, role) {
			ps.Set(role)
		}
	})

	access, err = j.signer.GenerateJwt(data.UserID, "", jwt.ClaimStrings{data.TokenInfo.GetClientID()}, data.TokenInfo.GetAccessExpiresIn(), auth.AccessTokenClaims{
		Perms: ps,
	})

	if isGenRefresh {
		t := uuid.NewHash(sha256.New(), uuid.New(), []byte(access), 5).String()
		refresh = base64.URLEncoding.EncodeToString([]byte(t))
		refresh = strings.ToUpper(strings.TrimRight(refresh, "="))
	}

	return
}
