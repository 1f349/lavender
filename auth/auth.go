package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/1f349/lavender/database"
	"net/http"
)

type Factor byte

const (
	// FactorAuthorized defines the "authorized" state of a session
	FactorAuthorized Factor = iota
	FactorFirst
	FactorSecond
)

type Provider interface {
	// Factor defines the factors potentially supported by the provider
	// Some factors might be unavailable due to user preference
	Factor() Factor

	// Name defines a string value for the provider, useful for template switching
	Name() string

	// RenderData stores values to send to the templating function
	RenderData(ctx context.Context, req *http.Request, user *database.User, data map[string]any) error

	// AttemptLogin processes the login request
	AttemptLogin(ctx context.Context, req *http.Request, user *database.User) error
}

var (
	// ErrRequiresSecondFactor notifies the ServeHTTP function to ask for another factor
	ErrRequiresSecondFactor = errors.New("requires second factor")
	// ErrRequiresPreviousFactor is a generic error for providers which require a previous factor
	ErrRequiresPreviousFactor = errors.New("requires previous factor")
	// ErrUserDoesNotSupportFactor is a generic error for providers with are unable to support the user
	ErrUserDoesNotSupportFactor = errors.New("user does not support factor")
)

type UserSafeError struct {
	Display  string
	Code     int
	Internal error
}

func (e UserSafeError) Error() string {
	return fmt.Sprintf("%s [%d]: %v", e.Display, e.Code, e.Internal)
}

func (e UserSafeError) Unwrap() error {
	return e.Internal
}

func BasicUserSafeError(code int, message string) UserSafeError {
	return UserSafeError{
		Code:     code,
		Display:  message,
		Internal: errors.New(message),
	}
}

func AdminSafeError(inner error) UserSafeError {
	return UserSafeError{
		Code:     http.StatusInternalServerError,
		Display:  "Internal server error",
		Internal: inner,
	}
}

type RedirectError struct {
	Target string
	Code   int
}

func (e RedirectError) TargetUrl() string { return e.Target }

func (e RedirectError) Error() string {
	return fmt.Sprintf("redirect to '%s'", e.Target)
}

type lookupUserDB interface {
	GetUser(ctx context.Context, subject string) (database.User, error)
}

func lookupUser(ctx context.Context, db lookupUserDB, subject string, resolvesTwoFactor bool, user *database.User) error {
	getUser, err := db.GetUser(ctx, subject)
	if err != nil {
		return err
	}
	*user = getUser
	if user.NeedFactor && !resolvesTwoFactor {
		return ErrRequiresSecondFactor
	}
	return nil
}
