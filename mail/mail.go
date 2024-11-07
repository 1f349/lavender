package mail

import (
	"embed"
	"errors"
	"fmt"
	"github.com/1f349/overlapfs"
	"github.com/1f349/simplemail"
	"github.com/emersion/go-message/mail"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed templates/*.go.html templates/*.go.txt
var embeddedTemplates embed.FS

type Mail struct {
	mail *simplemail.SimpleMail
	name string
}

func New(sender *simplemail.Mail, wd, name string) (*Mail, error) {
	var o fs.FS = embeddedTemplates
	o, _ = fs.Sub(o, "templates")
	if wd != "" {
		mailDir := filepath.Join(wd, "mail-templates")
		err := os.Mkdir(mailDir, os.ModePerm)
		if err == nil || errors.Is(err, os.ErrExist) {
			wdFs := os.DirFS(mailDir)
			o = overlapfs.OverlapFS{A: embeddedTemplates, B: wdFs}
		}
	}

	simpleMail, err := simplemail.New(sender, o)
	return &Mail{
		mail: simpleMail,
		name: name,
	}, err
}

func (m *Mail) SendEmailTemplate(templateName, subject, nameOfUser string, to *mail.Address, data map[string]any) error {
	return m.mail.Send(templateName, fmt.Sprintf("%s - %s", subject, m.name), to, map[string]any{
		"ServiceName": m.name,
		"Name":        nameOfUser,
		"Data":        data,
	})
}
