package settings

var (
	// 2 factor authentication flags
	PasswordChange2FA bool = false // changing password
	LoginChange2FA    bool = false // changing login
	UserCreate2FA     bool = false // register
	UserDelete2FA     bool = false // delete account
	TokenGet2FA       bool = false // login
	DebugMode         bool = false
)

const (
	PASSWORD_MIN_ITERATIONS_COUNT = 5000
	PASSWORD_HASH_LENGTH          = 32
	PASSWORD_SALT_SIZE            = 16
	TOKEN_SALT_SIZE               = 16
)
