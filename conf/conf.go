package conf

import (
	"github.com/1f349/lavender/utils"
	"github.com/1f349/simplemail"
)

type Conf struct {
	Listen      string          `yaml:"listen"`
	BaseUrl     *utils.URL      `yaml:"baseUrl"`
	ServiceName string          `yaml:"serviceName"`
	Issuer      string          `yaml:"issuer"`
	Kid         string          `yaml:"kid"`
	Namespace   string          `yaml:"namespace"`
	OtpIssuer   string          `yaml:"otpIssuer"`
	Mail        simplemail.Mail `yaml:"mail"`
}
