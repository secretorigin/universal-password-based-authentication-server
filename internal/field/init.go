package field

/*
	This is file for information which is needed for fields personalization
*/

var (
	// password
	PASSWORD_SALT_LENGTH          = 32
	PASSWORD_HASH_LENGTH          = 32
	PASSWORD_SALT_CHARS           = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	PASSWORD_MIN_ITERATIONS_COUNT = 5000

	// token
	TOKEN_REGEX                  = "^[A-Za-z0-9-_]*\\.[A-Za-z0-9-_]*\\.[A-Za-z0-9-_]*$"
	TOKEN_SALT_LENGTH            = 32
	TOKEN_SALT_CHARS             = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	TOKEN_RARITY                 = 100000
	TOKEN_LIFETIME_MINUTES       = 15
	REFRESH_TOKEN_LIFETIME_HOURS = 24 * 30
	TOKEN_MAX_COUNT              = 16
)
