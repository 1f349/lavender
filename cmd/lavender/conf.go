package main

import loginServiceManager "github.com/1f349/lavender/issuer"

type startUpConfig struct {
	Listen      string                          `json:"listen"`
	BaseUrl     string                          `json:"base_url"`
	PrivateKey  string                          `json:"private_key"`
	Issuer      string                          `json:"issuer"`
	SsoServices []loginServiceManager.SsoConfig `json:"sso_services"`
}
