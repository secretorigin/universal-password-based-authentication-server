package apierror

type APIError interface {
	Error() string
	PublicMsg() string
	Status() int
}

type sentinelAPIError struct {
	err    string
	msg    string
	status int
}

func (e sentinelAPIError) Error() string {
	return e.err
}

func (e sentinelAPIError) PublicMsg() string {
	return e.msg
}

func (e sentinelAPIError) Status() int {
	return e.status
}
