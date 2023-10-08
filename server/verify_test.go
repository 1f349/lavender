package server

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/MrMelon54/mjwt"
	"github.com/MrMelon54/mjwt/auth"
	"github.com/MrMelon54/mjwt/claims"
	"github.com/julienschmidt/httprouter"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVerifyHandler(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	invalidSigner := mjwt.NewMJwtSigner("Invalid Issuer", privKey)
	h := HttpServer{
		conf:   Conf{Issuer: "Test Issuer"},
		signer: mjwt.NewMJwtSigner("Test Issuer", privKey),
	}

	// test for missing bearer response
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "https://example.localhost", nil)
	h.verifyHandler(rec, req, httprouter.Params{})
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "Missing bearer\n", rec.Body.String())

	// test for invalid token response
	rec = httptest.NewRecorder()
	req.Header.Set("Authorization", "Bearer abcd")
	h.verifyHandler(rec, req, httprouter.Params{})
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "Invalid token\n", rec.Body.String())

	// test for invalid issuer response
	rec = httptest.NewRecorder()
	accessToken, err := invalidSigner.GenerateJwt("a", "a", nil, 15*time.Minute, auth.AccessTokenClaims{
		Perms: claims.NewPermStorage(),
	})
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	h.verifyHandler(rec, req, httprouter.Params{})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "Invalid issuer\n", rec.Body.String())

	// test for invalid issuer response
	rec = httptest.NewRecorder()
	accessToken, err = h.signer.GenerateJwt("a", "a", nil, 15*time.Minute, auth.AccessTokenClaims{
		Perms: claims.NewPermStorage(),
	})
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	h.verifyHandler(rec, req, httprouter.Params{})
	assert.Equal(t, http.StatusOK, rec.Code)
}
