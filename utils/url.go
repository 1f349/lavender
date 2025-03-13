package utils

import (
	"encoding"
	"net/url"
	"path"
)

var _ encoding.TextMarshaler = (*URL)(nil)
var _ encoding.TextUnmarshaler = (*URL)(nil)

type URL struct{ *url.URL }

func MustParse(rawURL string) *URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return &URL{u}
}

func (u *URL) Resolve(paths ...string) *URL {
	return &URL{URL: u.URL.ResolveReference(&url.URL{Path: path.Join(paths...)})}
}

func (u *URL) MarshalText() (text []byte, err error) {
	return []byte(u.URL.String()), nil
}

func (u *URL) UnmarshalText(text []byte) error {
	parse, err := url.Parse(string(text))
	if err != nil {
		return err
	}

	u.URL = parse
	return nil
}
