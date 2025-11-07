package providers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/1f349/lavender/auth"
	"github.com/1f349/lavender/auth/authContext"
	"github.com/1f349/lavender/auth/process"
	"github.com/1f349/lavender/database"
	"github.com/xlzd/gotp"
)

func isDigitsSupported(digits int64) bool {
	return digits >= 6 && digits <= 8
}

type otpLoginDB interface {
	GetOtp(ctx context.Context, subject string) (database.GetOtpRow, error)
}

var _ auth.Provider = (*OtpLogin)(nil)
var _ auth.Form = (*OtpLogin)(nil)

type OtpLogin struct {
	DB otpLoginDB
}

func (o *OtpLogin) AccessState() process.State { return process.StateBasic }

func (o *OtpLogin) Name() string { return "otp" }

func (o *OtpLogin) String() string { return "%Provider(otp)" }

func (o *OtpLogin) SupportsUser(user *database.User) bool {
	return user != nil && user.OtpSecret != "" && isDigitsSupported(user.OtpDigits)
}

func (o *OtpLogin) RenderTemplate(ctx authContext.TemplateContext) error {
	user := ctx.User()
	if user == nil || user.Subject == "" {
		return fmt.Errorf("requires previous factor")
	}
	if user.OtpSecret == "" || !isDigitsSupported(user.OtpDigits) {
		return fmt.Errorf("user does not support factor")
	}

	// TODO: is this right?
	ctx.Render(map[string]any{
		"Redirect": "/",
	})

	// no need to provide render data
	return nil
}

func (o *OtpLogin) AttemptLogin(ctx authContext.FormContext) error {
	user := ctx.User()
	if user == nil || user.Subject == "" {
		return fmt.Errorf("requires previous factor")
	}
	if user.OtpSecret == "" || !isDigitsSupported(user.OtpDigits) {
		return fmt.Errorf("user does not support factor")
	}

	code := ctx.Request().FormValue("code")

	if !validateTotp(user.OtpSecret, int(user.OtpDigits), code) {
		return auth.BasicUserSafeError(http.StatusBadRequest, "invalid OTP code")
	}

	ctx.UpdateSession(process.UpdateLoginProcessData{
		State: process.StateAuthenticated,
	})
	return nil
}

var ErrInvalidOtpCode = errors.New("invalid OTP code")

func (o *OtpLogin) VerifyOtpCode(ctx context.Context, subject, code string) error {
	otp, err := o.DB.GetOtp(ctx, subject)
	if err != nil {
		return err
	}
	if !validateTotp(otp.OtpSecret, int(otp.OtpDigits), code) {
		return ErrInvalidOtpCode
	}
	return nil
}

func validateTotp(secret string, digits int, code string) bool {
	totp := gotp.NewTOTP(secret, int(digits), 30, nil)
	return verifyTotp(totp, code)
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
