package utils

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestAge(t *testing.T) {
	lGmt := time.FixedZone("GMT", 0)
	lBst := time.FixedZone("BST", 60*60)

	tPast := time.Date(1939, time.January, 5, 0, 0, 0, 0, lGmt)
	tPastDst := time.Date(2001, time.January, 5, 1, 0, 0, 0, lBst)
	tCur := time.Date(2005, time.January, 5, 0, 30, 0, 0, lGmt)
	tCurDst := time.Date(2005, time.January, 5, 0, 30, 0, 0, lBst)
	tFut := time.Date(2008, time.January, 5, 0, 0, 0, 0, time.UTC)

	ageTimeNow = func() time.Time { return tCur }
	assert.Equal(t, 65, Age(tPast))
	assert.Equal(t, 3, Age(tPastDst))
	assert.Equal(t, 0, Age(tFut))

	ageTimeNow = func() time.Time { return tCurDst }
	assert.Equal(t, 66, Age(tPast))
	assert.Equal(t, 4, Age(tPastDst))
	fmt.Println(tPastDst.AddDate(4, 0, 0).UTC(), tCur.UTC())
	assert.Equal(t, 0, Age(tFut))
}
