package database

import (
	"fmt"
	"github.com/1f349/lavender/database/types"
	"github.com/hardfinhq/go-date"
	"github.com/mrmelon54/pronouns"
	"golang.org/x/text/language"
	"net/url"
	"time"
)

type ProfilePatch struct {
	Name      string            `json:"name"`
	Picture   string            `json:"picture"`
	Website   string            `json:"website"`
	Pronouns  types.UserPronoun `json:"pronouns"`
	Birthdate date.NullDate     `json:"birthdate"`
	Zone      types.UserZone    `json:"zone"`
	Locale    types.UserLocale  `json:"locale"`
}

func (p *ProfilePatch) ParseFromForm(v url.Values) (safeErrs []error) {
	var err error
	p.Name = v.Get("name")
	p.Picture = v.Get("picture")
	p.Website = v.Get("website")
	if v.Has("reset_pronouns") {
		p.Pronouns.Pronoun = pronouns.TheyThem
	} else {
		p.Pronouns.Pronoun, err = pronouns.FindPronoun(v.Get("pronouns"))
		if err != nil {
			safeErrs = append(safeErrs, fmt.Errorf("invalid pronoun selected"))
		}
	}
	if v.Has("reset_birthdate") || v.Get("birthdate") == "" {
		p.Birthdate = date.NullDate{}
	} else {
		p.Birthdate = date.NullDate{Valid: true}
		p.Birthdate.Date, err = date.FromString(v.Get("birthdate"))
		if err != nil {
			safeErrs = append(safeErrs, fmt.Errorf("invalid time selected"))
		}
	}
	if v.Has("reset_zoneinfo") {
		p.Zone.Location = time.UTC
	} else {
		p.Zone.Location, err = time.LoadLocation(v.Get("zoneinfo"))
		if err != nil {
			safeErrs = append(safeErrs, fmt.Errorf("invalid timezone selected"))
		}
	}
	if v.Has("reset_locale") {
		p.Locale.Tag = language.AmericanEnglish
	} else {
		p.Locale.Tag, err = language.Parse(v.Get("locale"))
		if err != nil {
			safeErrs = append(safeErrs, fmt.Errorf("invalid language selected"))
		}
	}
	return
}
