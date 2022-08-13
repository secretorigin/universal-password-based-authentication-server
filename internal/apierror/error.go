package apierror

var (
	InternalServerError = sentinelAPIError{msg: "Internal Server Error", status: 500}
	Database            = sentinelAPIError{msg: "Database Error", status: 500}
	NotFound            = sentinelAPIError{msg: "Not Found", status: 404}

	BodyFormat = sentinelAPIError{msg: "Wrong Body Format", status: 400}

	AuthenticationInfo = sentinelAPIError{msg: "Wrong Access Part", status: 400}
	Password           = sentinelAPIError{msg: "Wrong Password", status: 400}
	Login              = sentinelAPIError{msg: "User not exist", status: 400}
	ConfirmInfo        = sentinelAPIError{msg: "Wrong confirm info", status: 400}

	LoginAlreadyExist = sentinelAPIError{msg: "Login Already Exist", status: 400}
	FieldFormat       = sentinelAPIError{msg: "Wrong Field Format", status: 400}
)

func New(text string, status int) APIError {
	return sentinelAPIError{msg: text, status: status}
}
