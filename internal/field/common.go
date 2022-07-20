package field

import (
	"math/rand"
	"strings"
)

func Random(length uint, chars []rune) string {
	var b strings.Builder

	var i uint
	for i = 0; i < length; i++ {
		b.WriteRune(chars[rand.Intn(len(chars))])
	}
	return b.String()
}
