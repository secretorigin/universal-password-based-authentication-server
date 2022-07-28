package settings

// 2FA parameters
var (
	// 2 factor authentication flags
	PasswordChange2FA bool = false // changing password
	LoginChange2FA    bool = false // changing login
	UserCreate2FA     bool = false // register
	UserDelete2FA     bool = false // delete account
	TokenGet2FA       bool = false // login

	TemporaryPasswordSend  func(string) string
	TemporaryPasswordRegex string = ""
)

// crypto parameters
const (
	PASSWORD_MIN_ITERATIONS_COUNT = 5000
	PASSWORD_HASH_LENGTH          = 32
	PASSWORD_SALT_SIZE            = 16
	TOKEN_SALT_SIZE               = 16
)

// other
var (
	DebugMode bool = false
)

// fields
const (
	LOGIN_REGEX    string = ""
	PASSWORD_REGEX string = ""
	TOKEN_REGEX    string = ""
)
