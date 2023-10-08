package pages

import (
	"embed"
	_ "embed"
	"github.com/1f349/overlapfs"
	"html/template"
	"os"
	"path/filepath"
)

var (
	//go:embed *.go.html
	flowPages     embed.FS
	FlowTemplates *template.Template
)

func LoadPages(wd string) error {
	wwwDir := filepath.Join(wd, "www")
	err := os.Mkdir(wwwDir, os.ModePerm)
	if err != nil {
		return nil
	}
	wdFs := os.DirFS(wwwDir)
	o := overlapfs.OverlapFS{A: flowPages, B: wdFs}
	FlowTemplates, err = template.ParseFS(o, "*.go.html")
	return err
}
