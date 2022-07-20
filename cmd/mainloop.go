package cmd

import (
	"fmt"
	"log"
	"net/http"

	_ "github.com/lib/pq"

	_ "github.com/p2034/universal-password-based-authentication-server/internal/request"
	"github.com/p2034/universal-password-based-authentication-server/internal/settings"
)

func StartServer(conf settings.ServerConf) {
	http.HandleFunc("/user/create", request.userCreateHandler)

	host := fmt.Sprintf("%s:%d", conf.Host, conf.Port)

	log.Println("Server is listening on host: " + host)
	http.ListenAndServe(host, nil)
}
