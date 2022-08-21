package apierror

import "errors"

var (
	BodyDecode = sentinelAPIError{
		err:    errors.New("can not decode body"),
		msg:    "Bad Request",
		debug:  "-",
		status: 4040}

	NotFound = sentinelAPIError{
		err:    errors.New("wrong url or method"),
		msg:    "Not Found",
		debug:  "-",
		status: 404}

	FieldFormat = sentinelAPIError{
		err:    errors.New("wrong format of the field"),
		msg:    "Bad Request",
		debug:  "-",
		status: 400}

	LoginAlreadyExist = sentinelAPIError{
		err:    errors.New("login already exist"),
		msg:    "Bad Request",
		debug:  "-",
		status: 400}

	Access = sentinelAPIError{
		err:    errors.New("wrong access data"),
		msg:    "Access Error",
		debug:  "-",
		status: 400}

	ParseToken = sentinelAPIError{
		err:    errors.New("can not parse token"),
		msg:    "Bad Request",
		debug:  "-",
		status: 400}

	WrongToken = sentinelAPIError{
		err:    errors.New("wrong token"),
		msg:    "Access Error",
		debug:  "-",
		status: 400}

	CheckToken = sentinelAPIError{
		err:    errors.New("check token"),
		msg:    "Access Error",
		debug:  "-",
		status: 400}

	WrongPassword = sentinelAPIError{
		err:    errors.New("wrong password"),
		msg:    "Access Error",
		debug:  "-",
		status: 400}

	CheckPassword = sentinelAPIError{
		err:    errors.New("check password"),
		msg:    "Access Error",
		debug:  "-",
		status: 400}

	WrongVerificationCode = sentinelAPIError{
		err:    errors.New("wrong verification code"),
		msg:    "Confirmation Error",
		debug:  "-",
		status: 400}

	WrongVerificationToken = sentinelAPIError{
		err:    errors.New("wrong verification token"),
		msg:    "Confirmation Error",
		debug:  "-",
		status: 400}

	CheckVerificationToken = sentinelAPIError{
		err:    errors.New("check verification token"),
		msg:    "Confirmation Error",
		debug:  "-",
		status: 400}
)

func New(err error, debug string, msg string, status int) APIError {
	return sentinelAPIError{err: err, msg: msg, debug: debug, status: status}
}
