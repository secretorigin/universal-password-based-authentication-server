package crypto

import "crypto/rand"

func GenSalt(size int) []byte {
	salt := make([]byte, size)
	rand.Read(salt)
	return salt
}
