package auth

import (
	"github.com/1f349/lavender/auth/process"
)

type Provider interface {
	// AccessState defines the state at which the provider is allowed to show.
	// Some factors might be unavailable due to user preference.
	AccessState() process.State

	// Name defines a string value for the provider.
	Name() string
}
