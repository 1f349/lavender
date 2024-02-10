package server

import (
	"bufio"
	"strings"
)

func HasRole(roles, test string) bool {
	sc := bufio.NewScanner(strings.NewReader(roles))
	sc.Split(bufio.ScanWords)
	for sc.Scan() {
		if sc.Text() == test {
			return true
		}
	}
	return false
}

func ForEachRole(roles string, next func(role string)) {
	sc := bufio.NewScanner(strings.NewReader(roles))
	sc.Split(bufio.ScanWords)
	for sc.Scan() {
		next(sc.Text())
	}
}
