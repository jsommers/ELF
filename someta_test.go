package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"github.com/iovisor/gobpf/bcc"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
)

var port = 8080
var host = ""
var bpfInput = "someta_bpf.c"

func init() {
	flag.IntVar(&port, "port", 8080, "Set listen port for REST API daemon")
	flag.IntVar(&port, "p", 8080, "Set listen port for REST API daemon")
	flag.StringVar(&host, "host", "", "Host address for REST daemon to listen on")
}

func main() {
	flag.Parse()

	contents, err := ioutil.ReadFile(bpfInput)
	if err != nil {
		log.Printf("Couldn't open eBPF file %s\n", bpf_input)
		log.Fatal(err)
	}
	buf := bytes.NewBuffer(contents)
	contentsStr := buf.String()

	var srv http.Server
	srv.Addr = fmt.Sprintf("%s:%d", host, port)

	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint

		// We received an interrupt signal, shut down.
		if err := srv.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			log.Printf("HTTP server Shutdown: %v", err)
		}
		close(idleConnsClosed)
	}()

	getStatus := func(w http.ResponseWriter, req *http.Request) {
		var status = map[string]string{
			"info":  "hello",
			"other": "stuff",
		}
		w.Header().Add("Content-Type", "application/json")

		if req.Method == "GET" {
			jsonIo := json.NewEncoder(w)
			jsonIo.Encode(status)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}

	http.HandleFunc("/someta", getStatus)

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		// Error starting or closing listener:
		log.Fatalf("HTTP server ListenAndServe: %v", err)
	}

	<-idleConnsClosed
}
