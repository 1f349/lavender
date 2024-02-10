package database

import (
	"github.com/go-oauth2/oauth2/v4"
	"time"
)

type User struct {
	Sub           string    `json:"sub"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	Roles         string    `json:"roles"`
	UpdatedAt     time.Time `json:"updated_at"`
	Active        bool      `json:"active"`
}

type ClientInfoDbOutput struct {
	Sub, Name, Secret, Domain, Owner, Perms string
	Public, SSO, Active                     bool
}

var _ oauth2.ClientInfo = &ClientInfoDbOutput{}

func (c *ClientInfoDbOutput) GetID() string     { return c.Sub }
func (c *ClientInfoDbOutput) GetSecret() string { return c.Secret }
func (c *ClientInfoDbOutput) GetDomain() string { return c.Domain }
func (c *ClientInfoDbOutput) IsPublic() bool    { return c.Public }
func (c *ClientInfoDbOutput) GetUserID() string { return c.Owner }

// GetName is an extra field for the oauth handler to display the application
// name
func (c *ClientInfoDbOutput) GetName() string { return c.Name }

// IsSSO is an extra field for the oauth handler to skip the user input stage
// this is for trusted applications to get permissions without asking the user
func (c *ClientInfoDbOutput) IsSSO() bool { return c.SSO }

// IsActive is an extra field for the app manager to get the active state
func (c *ClientInfoDbOutput) IsActive() bool { return c.Active }

// UsePerms is an extra field for the userinfo handler to return user permissions matching the requested values
func (c *ClientInfoDbOutput) UsePerms() string { return c.Perms }
