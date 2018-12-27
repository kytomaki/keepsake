package cmd

import (
	"testing"
	"time"
)

func TestMultipliedDuration(t *testing.T) {
	twoMinutes := 2 * time.Minute
	minute := MultipliedDuration(twoMinutes, 0.5)
	if minute != time.Minute {
		t.Errorf("Didn't expect minute to be: %s", minute)
	}
}
