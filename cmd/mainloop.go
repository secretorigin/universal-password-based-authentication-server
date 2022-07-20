package cmd

import (
	"fmt"
	"log"
	"net/http"

	_ "github.com/lib/pq"
)

type ServerConf struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

func StartServer(conf ServerConf) {
	http.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprintf(w, "all is ok")
	})

	host := fmt.Sprintf("%s:%d", conf.Host, conf.Port)

	log.Println("Server is listening on host: " + host)
	http.ListenAndServe(host, nil)
}
