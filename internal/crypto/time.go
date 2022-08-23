package crypto

import (
	"time"
)

func TimePassed(t time.Time, period time.Duration) bool {
	return time.Now().After(t.Add(period))
}
