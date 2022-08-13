package settings

// 2FA parameters
var (
	// 2 factor authentication flags
	PasswordChange2FA bool = false // changing password
	LoginChange2FA    bool = false // changing login
	UserCreate2FA     bool = false // register
	UserDelete2FA     bool = false // delete account
	TokenGet2FA       bool = false // login

	TemporaryPasswordSend func(string) string

	TemporaryPasswordRegex string = ""
	LoginRegex             string = "^[a-z][a-z0-9_]{4,14}[a-z0-9]$"
	PasswordRegex          string = `^[A-Za-z0-9\d@$!%*#?&_\-]{8,64}$`
	TokenRegex             string = `^[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*$`
)

// crypto parameters
const (
	PASSWORD_MIN_ITERATIONS_COUNT = 5000
	PASSWORD_HASH_LENGTH          = 32
	PASSWORD_SALT_SIZE            = 16
	TOKEN_SALT_SIZE               = 16
	RESPONSE_MAX_TIME             = 500
)

// other
var (
	// it will print errors if they will be in usage process
	DebugMode bool = false
)
