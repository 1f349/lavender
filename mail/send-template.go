package mail

import (
	"bytes"
	"fmt"
	"github.com/1f349/lavender/mail/templates"
	"github.com/emersion/go-message/mail"
)

func (m *Mail) SendEmailTemplate(templateName, subject, nameOfUser string, to *mail.Address, data map[string]any) error {
	var bufHtml, bufTxt bytes.Buffer
	templates.RenderMailTemplate(&bufHtml, &bufTxt, templateName, map[string]any{
		"ServiceName": m.Name,
		"Name":        nameOfUser,
		"Data":        data,
	})
	return m.SendMail(fmt.Sprintf("%s - %s", subject, m.Name), []*mail.Address{to}, &bufHtml, &bufTxt)
}
