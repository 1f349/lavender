package server

import (
	"bytes"
	"encoding/base64"
	auth2 "github.com/1f349/lavender/auth"
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/pages"
	"github.com/julienschmidt/httprouter"
	"github.com/skip2/go-qrcode"
	"github.com/xlzd/gotp"
	"html/template"
	"image/png"
	"net/http"
	"time"
)

func (h *httpServer) editOtpPost(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, auth auth2.UserAuth) {
	if req.Method == http.MethodPost && req.FormValue("remove") == "1" {
		if !req.Form.Has("code") {
			// render page
			pages.RenderPageTemplate(rw, "remove-otp", map[string]any{
				"ServiceName": h.conf.ServiceName,
			})
			return
		}

		otpInput := req.Form.Get("code")
		err := h.authOtp.VerifyOtpCode(req.Context(), auth.Subject, otpInput)
		if err != nil {
			http.Error(rw, "Invalid OTP code", http.StatusBadRequest)
			return
		}

		if h.DbTx(rw, func(tx *database.Queries) error {
			return tx.DeleteOtp(req.Context(), auth.Subject)
		}) {
			return
		}

		http.Redirect(rw, req, "/", http.StatusFound)
		return
	}

	var digits int
	switch req.FormValue("digits") {
	case "6":
		digits = 6
	case "7":
		digits = 7
	case "8":
		digits = 8
	default:
		http.Error(rw, "400 Bad Request: Invalid number of digits for OTP code", http.StatusBadRequest)
		return
	}

	secret := req.FormValue("secret")
	if !gotp.IsSecretValid(secret) {
		http.Error(rw, "400 Bad Request: Invalid secret", http.StatusBadRequest)
		return
	}

	if secret == "" {
		// get user email
		var email string
		if h.DbTx(rw, func(tx *database.Queries) error {
			var err error
			email, err = tx.GetUserEmail(req.Context(), auth.Subject)
			return err
		}) {
			return
		}

		secret = gotp.RandomSecret(64)
		if secret == "" {
			http.Error(rw, "500 Internal Server Error: failed to generate OTP secret", http.StatusInternalServerError)
			return
		}
		totp := gotp.NewTOTP(secret, digits, 30, nil)
		otpUri := totp.ProvisioningUri(email, h.conf.OtpIssuer)
		code, err := qrcode.New(otpUri, qrcode.Medium)
		if err != nil {
			http.Error(rw, "500 Internal Server Error: failed to generate QR code", http.StatusInternalServerError)
			return
		}
		qrImg := code.Image(60 * 4)
		qrBounds := qrImg.Bounds()
		qrWidth := qrBounds.Dx()

		qrBuf := new(bytes.Buffer)
		if png.Encode(qrBuf, qrImg) != nil {
			http.Error(rw, "500 Internal Server Error: failed to generate PNG image of QR code", http.StatusInternalServerError)
			return
		}

		// render page
		pages.RenderPageTemplate(rw, "edit-otp", map[string]any{
			"ServiceName": h.conf.ServiceName,
			"OtpQr":       template.URL("data:qrImg/png;base64," + base64.StdEncoding.EncodeToString(qrBuf.Bytes())),
			"QrWidth":     qrWidth,
			"OtpUrl":      otpUri,
			"OtpSecret":   secret,
			"OtpDigits":   digits,
		})
		return
	}

	totp := gotp.NewTOTP(secret, digits, 30, nil)

	if !verifyTotp(totp, req.FormValue("code")) {
		http.Error(rw, "400 Bad Request: invalid OTP code", http.StatusBadRequest)
		return
	}

	if h.DbTx(rw, func(tx *database.Queries) error {
		return tx.SetOtp(req.Context(), database.SetOtpParams{
			Subject:   auth.Subject,
			OtpSecret: secret,
			OtpDigits: int64(digits),
		})
	}) {
		return
	}

	http.Redirect(rw, req, "/", http.StatusFound)
}

func verifyTotp(totp *gotp.TOTP, code string) bool {
	t := time.Now()
	if totp.VerifyTime(code, t) {
		return true
	}
	if totp.VerifyTime(code, t.Add(-30*time.Second)) {
		return true
	}
	return totp.VerifyTime(code, t.Add(30*time.Second))
}
