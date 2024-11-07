package utils

import (
	"time"
)

var ageTimeNow = time.Now

func Age(t time.Time) int {
	n := ageTimeNow()

	// the birthday is in the future so the age is 0
	if n.Before(t) {
		return 0
	}

	// the year difference
	dy := n.Year() - t.Year()

	// the birthday in the current year
	tCurrent := t.AddDate(dy, 0, 0)

	// minus 1 if the birthday has not yet occurred in the current year
	if tCurrent.Before(n) {
		dy -= 1
	}
	return dy
}
