package pages

import (
	"bytes"
	"embed"
	_ "embed"
	"errors"
	"github.com/1f349/lavender/logger"
	"github.com/1f349/lavender/utils"
	"github.com/1f349/overlapfs"
	"html/template"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

var (
	//go:embed *.go.html assets/*.css
	wwwPages     embed.FS
	wwwTemplates *template.Template
	loadOnce     utils.Once[error]
	cssAssetMap  = make(map[string][]byte)
)

func LoadPages(wd string) error {
	return loadOnce.Do(func() (err error) {
		var o fs.FS = wwwPages
		if wd != "" {
			wwwDir := filepath.Join(wd, "www")
			err = os.Mkdir(wwwDir, os.ModePerm)
			if err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			wdFs := os.DirFS(wwwDir)
			o = overlapfs.OverlapFS{A: wwwPages, B: wdFs}
		}
		wwwTemplates, err = template.New("pages").Funcs(template.FuncMap{
			"emailHide": EmailHide,
		}).ParseFS(o, "*.go.html")

		glob, err := fs.Glob(o, "assets/*")
		if err != nil {
			return err
		}
		for _, i := range glob {
			cssAssetMap[i], err = fs.ReadFile(o, i)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func RenderPageTemplate(wr io.Writer, name string, data any) {
	err := wwwTemplates.ExecuteTemplate(wr, name+".go.html", data)
	if err != nil {
		logger.Logger.Warn("Failed to render page", "name", name, "err", err)
	}
}

func RenderCss(name string) io.ReadSeeker {
	b, ok := cssAssetMap[name]
	if !ok {
		return nil
	}
	return bytes.NewReader(b)
}

func EmailHide(a string) string {
	b := []byte(a)
	for i := range b {
		if b[i] != '@' && b[i] != '.' {
			b[i] = 'x'
		}
	}
	return string(b)
}
