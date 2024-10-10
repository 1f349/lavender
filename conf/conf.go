package conf

import (
	"github.com/1f349/lavender/issuer"
	"github.com/1f349/lavender/mail"
)

type Conf struct {
	Listen      string             `yaml:"listen"`
	BaseUrl     string             `yaml:"baseUrl"`
	ServiceName string             `yaml:"serviceName"`
	Issuer      string             `yaml:"issuer"`
	Kid         string             `yaml:"kid"`
	Namespace   string             `yaml:"namespace"`
	OtpIssuer   string             `yaml:"otpIssuer"`
	Mail        mail.Mail          `yaml:"mail"`
	SsoServices []issuer.SsoConfig `yaml:"ssoServices"`
}
