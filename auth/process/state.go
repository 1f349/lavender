package process

// State defines the currently reached authentication state
type State byte

const (
	// StateUnauthorized defines the "unauthorized" state of a session
	StateUnauthorized State = iota
	// StateBase defines the "username" only user state
	// This state is for providing a username to allow redirecting to oauth clients
	StateBase
	// StateBasic defines the "username and password with no OTP" user state
	// This is skipped if OTP/passkey is optional and not enabled for the user
	StateBasic
	// StateAuthenticated defines the "logged in" user state
	StateAuthenticated
	// StateSudo defines the "sudo" user state
	// This state is temporary and has a configurable duration
	StateSudo
)

func (s State) IsValid() bool { return s <= StateSudo }

func (s State) IsLoggedIn() bool { return s >= StateAuthenticated }

func (s State) IsSudoAvailable() bool { return s == StateSudo }
