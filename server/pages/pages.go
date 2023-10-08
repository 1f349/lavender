package pages

import (
	"embed"
	_ "embed"
	"html/template"
	"os"
)

var (
	//go:embed pages/*
	flowPages     embed.FS
	flowTemplates *template.Template
)

func LoadPages(wd string) {
	wdFs := os.DirFS(wd)

	flowPages.Open()
}
