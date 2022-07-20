package field

import (
	"crypto/sha256"
	"encoding/hex"
	"math/rand"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/pbkdf2"
)

type PasswordCache struct {
	Hash       string
	Salt       string
	Iterations int
}

/* . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
	generate random salt and iterations count, find password hash
	and unite all params in one structure
. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . */
func GenPasswordCache(password string) PasswordCache {
	var cache PasswordCache

	cache.Salt = Random(uint(PASSWORD_SALT_LENGTH), []rune(PASSWORD_SALT_CHARS))
	cache.Iterations = int(rand.Uint32())%1000 + PASSWORD_MIN_ITERATIONS_COUNT
	cache.Hash = hex.EncodeToString(pbkdf2.Key(
		[]byte(password),
		[]byte(cache.Salt),
		int(cache.Iterations),
		PASSWORD_HASH_LENGTH,
		sha256.New,
	))

	return cache
}

/* . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
	generate password hash using iterations and salt from cache
	and compare with hash from cache
. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . */
func CheckPasswordCache(password string, cache PasswordCache) bool {
	rehash := hex.EncodeToString(pbkdf2.Key(
		[]byte(password),
		[]byte(cache.Salt),
		int(cache.Iterations),
		PASSWORD_HASH_LENGTH,
		sha256.New,
	))

	return (rehash == cache.Hash)
}
