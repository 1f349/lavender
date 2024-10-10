package auth

import (
	"context"
	"github.com/1f349/lavender/database"
	"github.com/xlzd/gotp"
	"net/http"
	"time"
)

func isDigitsSupported(digits int64) bool {
	return digits >= 6 && digits <= 8
}

type otpLoginDB interface {
	lookupUserDB
	CheckLogin(ctx context.Context, un, pw string) (database.CheckLoginResult, error)
}

var _ Provider = (*OtpLogin)(nil)

type OtpLogin struct {
	db otpLoginDB
}

func (b *OtpLogin) Factor() Factor {
	return FactorSecond
}

func (b *OtpLogin) Name() string { return "basic" }

func (b *OtpLogin) RenderData(_ context.Context, _ *http.Request, user *database.User, data map[string]any) error {
	if user.Subject == "" {
		return ErrRequiresPreviousFactor
	}
	if user.OtpSecret == "" || !isDigitsSupported(user.OtpDigits) {
		return ErrUserDoesNotSupportFactor
	}

	// no need to provide render data
	return nil
}

func (b *OtpLogin) AttemptLogin(ctx context.Context, req *http.Request, user *database.User) error {
	if user == nil || user.Subject == "" {
		return ErrRequiresPreviousFactor
	}
	if user.OtpSecret == "" || !isDigitsSupported(user.OtpDigits) {
		return ErrUserDoesNotSupportFactor
	}

	code := req.FormValue("code")

	totp := gotp.NewTOTP(user.OtpSecret, int(user.OtpDigits), 30, nil)
	if !verifyTotp(totp, code) {
		return BasicUserSafeError(http.StatusBadRequest, "invalid OTP code")
	}
	return nil
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
