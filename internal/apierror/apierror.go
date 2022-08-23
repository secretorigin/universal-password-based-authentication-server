package apierror

type APIError interface {
	Error() string
	Msg() string
	Debug() string
	Status() int
}

type sentinelAPIError struct {
	err    error
	debug  string
	msg    string
	status int
}

func (e sentinelAPIError) Error() string {
	if e.err == nil {
		return "-"
	}

	return e.err.Error()
}

func (e sentinelAPIError) Msg() string {
	return e.msg
}

func (e sentinelAPIError) Debug() string {
	return e.debug
}

func (e sentinelAPIError) Status() int {
	return e.status
}
