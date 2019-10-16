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

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bcc_common.h>
#include <bcc/libbpf.h>
*/
import "C"

var port = 8080
var host = ""
var bpfInput = "someta_bpf.c"
var netInterface = ""

func init() {
	flag.IntVar(&port, "port", 8080, "Set listen port for REST API daemon")
	flag.IntVar(&port, "p", 8080, "Set listen port for REST API daemon")
	flag.StringVar(&host, "host", "", "Host address for REST daemon to listen on")
	flag.StringVar(&netInterface, "i", "", "Interface name to use")
}

func main() {
	flag.Parse()

	contents, err := ioutil.ReadFile(bpfInput)
	if err != nil {
		log.Printf("Couldn't open eBPF file %s\n", bpf_input)
		log.Fatal(err)
	}
	buf := bytes.NewBuffer(contents)
	ebpfSource := buf.String()
	ebpf := bcc.NewModule(ebpfSource, []string{
		"-w",
		"-DRETURNCODE=" + ret,
		"-DCTXTYPE=" + ctxtype,
	})
	defer module.Close()
	fn, err := ebpf.Load("xdp_prog1", C.BPF_PROG_TYPE_XDP, 1, 65536)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load xdp prog: %v\n", err)
		os.Exit(1)
	}

	err = ebpf.AttachXDP(netInterface, fn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach xdp prog: %v\n", err)
		os.Exit(1)
	}

	defer func() {
		if err := ebpf.RemoveXDP(netInterface); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to remove XDP from %s: %v\n", device, err)
		}
	}()



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

	dropcnt := bpf.NewTable(module.TableId("dropcnt"), module)
	fmt.Printf("\n{IP protocol-number}: {total dropped pkts}\n")
	for it := dropcnt.Iter(); it.Next(); {
		key := bpf.GetHostByteOrder().Uint32(it.Key())
		value := bpf.GetHostByteOrder().Uint64(it.Leaf())

		if value > 0 {
			fmt.Printf("%v: %v pkts\n", key, value)
		}
	}
}
