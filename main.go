package main

import (
	"io"
	"log"
	"net"
	"net/http"
	"sync/atomic"

	"golang.org/x/sync/errgroup"
)

func pipe(dst io.WriteCloser, src io.Reader) func() error {
	return func() error {
		defer dst.Close()
		defer io.Copy(io.Discard, src) // nolint:errcheck
		_, err := io.Copy(dst, src)
		return err
	}
}

func main() {
	id := uint64(0)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := atomic.AddUint64(&id, 1)
		log.Println(id, "request for", r.Host)

		if r.Method != http.MethodConnect {
			log.Println(id, "invalid method", r.Method)
			http.Error(w, "invalid method", http.StatusMethodNotAllowed)
			return
		}

		serverConn, err := (&net.Dialer{}).DialContext(r.Context(), "tcp", r.Host)
		if err != nil {
			log.Println(id, "dial failed", err)
			http.Error(w, "dial failed", http.StatusServiceUnavailable)
			return
		}
		defer serverConn.Close()
		defer io.Copy(io.Discard, serverConn) // nolint:errcheck
		log.Println(id, "dial done")

		hijacker, ok := w.(http.Hijacker)
		if !ok {
			log.Println(id, "hijacker not available")
			http.Error(w, "hijacker not available", http.StatusServiceUnavailable)
			return
		}

		w.WriteHeader(http.StatusOK)

		clientConn, _, err := hijacker.Hijack()
		if err != nil {
			log.Println(id, "hijack failed", err)
			return
		}
		defer clientConn.Close()
		defer io.Copy(io.Discard, clientConn) // nolint:errcheck
		log.Println(id, "hijack done")

		group := errgroup.Group{}
		group.Go(pipe(serverConn, clientConn))
		group.Go(pipe(clientConn, serverConn))

		log.Println(id, "request done", group.Wait())
	})
	log.Fatal(http.ListenAndServe(":8888", handler))
}
