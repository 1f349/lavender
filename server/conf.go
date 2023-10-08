package server

import (
	"github.com/1f349/lavender/issuer"
	"github.com/1f349/lavender/utils"
)

type Conf struct {
	Listen         string             `json:"listen"`
	BaseUrl        string             `json:"base_url"`
	ServiceName    string             `json:"service_name"`
	Issuer         string             `json:"issuer"`
	SsoServices    []issuer.SsoConfig `json:"sso_services"`
	AllowedClients []utils.JsonUrl    `json:"allowed_clients"`
}
