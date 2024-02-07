package server

import (
	"github.com/1f349/lavender/issuer"
)

type Conf struct {
	Listen      string             `json:"listen"`
	BaseUrl     string             `json:"base_url"`
	ServiceName string             `json:"service_name"`
	Issuer      string             `json:"issuer"`
	SsoServices []issuer.SsoConfig `json:"sso_services"`
}
