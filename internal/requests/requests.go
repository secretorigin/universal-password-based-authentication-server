package requests

type access_body_part struct {
	Refresh_token string `json:"refresh_token"`
	Password      string `json:"password"`
}

type response_temporary_token_body struct {
	Temporary_token string `json:"temporary_token"`
}
