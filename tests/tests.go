package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

func main() {
	fmt.Println(test("my_login", "my_password"))
}

// tests without 2FA
func test(username string, password string) bool {
	// create user
	check := requestWithoutResponseBody(http.MethodPost, "/user/create", request_user_create_body{
		Login:    username,
		Password: password})
	if !check {
		return false
	}

	// get token (login)
	var resp_token_get response_token_get_body
	check = requestWithResponseBody(http.MethodPost, "/token/get", request_token_get_body{
		Login:    username,
		Password: password}, &resp_token_get)
	if !check {
		return false
	}

	// token check
	check = requestWithoutResponseBody(http.MethodPost, "/token/check", request_token_check_body{
		Token: resp_token_get.Token})
	if !check {
		return false
	}

	// password change
	var resp_password_change response_password_change_body
	check = requestWithResponseBody(http.MethodPatch, "/password/change", request_password_change_body{
		Access: access_body_part{
			Refresh_token: resp_token_get.Refresh_token,
			Password:      password},
		New_password:      "new_" + password,
		Logout_everywhere: true}, &resp_password_change)
	if !check {
		return false
	}
	password = "new_" + password

	// user delete
	check = requestWithoutResponseBody(http.MethodPost, "/user/delete", request_user_delete_body{
		Access: access_body_part{
			Refresh_token: resp_password_change.Refresh_token,
			Password:      password}})
	if !check {
		return false
	}

	return true
}

func requestWithoutResponseBody(method string, requesturl string, req_body interface{}) bool {
	bodybytes, _ := json.Marshal(req_body)
	client := &http.Client{}
	req, err := http.NewRequest(method, "http://localhost:10000"+requesturl, bytes.NewBuffer(bodybytes))
	req.Header.Set("Content-Type", "application/json")
	if err != nil {
		log.Println("Error:", err.Error())
		return false
	}
	resp, err := client.Do(req)
	defer resp.Body.Close()
	if err != nil {
		log.Println("Error:", err.Error())
		return false
	}
	if resp.StatusCode != http.StatusOK {
		log.Println(requesturl+" wrong response status:", resp.Status)
		return false
	}
	fmt.Println(requesturl+":", resp.Status)
	return true
}

func requestWithResponseBody(method string, requesturl string, req_body interface{}, res_body interface{}) bool {
	bodybytes, _ := json.Marshal(req_body)
	client := &http.Client{}
	req, err := http.NewRequest(method, "http://localhost:10000"+requesturl, bytes.NewBuffer(bodybytes))
	req.Header.Set("Content-Type", "application/json")
	if err != nil {
		log.Println("Error:", err.Error())
		return false
	}
	resp, err := client.Do(req)
	defer resp.Body.Close()
	if err != nil {
		log.Println("Error:", err.Error())
		return false
	}
	if resp.StatusCode != http.StatusOK {
		log.Println(requesturl+" wrong response status:", resp.Status)
		return false
	}
	fmt.Println(requesturl+":", resp.Status)
	bodybytes, err = io.ReadAll(resp.Body)
	if err != nil {
		log.Println("Error:", err.Error())
		return false
	}
	err = json.Unmarshal(bodybytes, res_body)
	if err != nil {
		log.Println("Error:", err.Error())
		return false
	}
	return true
}

type request_user_create_body struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type request_token_get_body struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type response_token_get_body struct {
	Token         string `json:"token"`
	Refresh_token string `json:"refresh_token"`
}

type request_token_check_body struct {
	Token string `json:"token"`
}

type request_password_change_body struct {
	Access            access_body_part `json:"access"`
	New_password      string           `json:"new_password"`
	Logout_everywhere bool             `json:"logout_everywhere"`
}

type response_password_change_body struct {
	Token         string `json:"token"`
	Refresh_token string `json:"refresh_token"`
}

type request_user_delete_body struct {
	Access access_body_part `json:"access"`
}

type access_body_part struct {
	Refresh_token string `json:"refresh_token"`
	Password      string `json:"password"`
}
