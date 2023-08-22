package main

import (
	"crypto/subtle"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/sha3"
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

func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", "", false
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return "", "", false
	}
	cs := string(c)
	username, password, ok = strings.Cut(cs, ":")
	if !ok {
		return "", "", false
	}
	return username, password, true
}

const (
	proxyAuthenticate  = "Proxy-Authenticate"
	proxyAuthorization = "Proxy-Authorization"
)

func handleAuthentication(w http.ResponseWriter, r *http.Request, expectedUsernameHash, expectedPasswordHash [64]byte, requireAuth bool) bool {
	if !requireAuth {
		return true
	}
	username, password, ok := parseBasicAuth(r.Header.Get(proxyAuthorization))
	if !ok {
		return false
	}
	usernameHash, passwordHash := sha3.Sum512([]byte(username)), sha3.Sum512([]byte(password))
	equalUsername := subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:])
	equalPassword := subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:])
	return (equalUsername & equalPassword) == 1
}

func main() {
	usernameEnv, hasUsername := os.LookupEnv("PROXY_USERNAME")
	passwordEnv, hasPassword := os.LookupEnv("PROXY_PASSWORD")
	usernameHash, passwordHash := sha3.Sum512([]byte(usernameEnv)), sha3.Sum512([]byte(passwordEnv))
	requireAuth := hasUsername && hasPassword
	if requireAuth {
		log.Println("authentication required")
	}

	id := uint64(0)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := atomic.AddUint64(&id, 1)
		log.Println(id, "request for", r.Host)

		if r.Method != http.MethodConnect {
			log.Println(id, "invalid method", r.Method)
			http.Error(w, "invalid method", http.StatusMethodNotAllowed)
			return
		}

		if !handleAuthentication(w, r, usernameHash, passwordHash, requireAuth) {
			log.Println(id, "authentication failed")
			w.Header().Add(proxyAuthenticate, "Basic")
			http.Error(w, "authentication required", http.StatusProxyAuthRequired)
			return
		}

		host, port, err := net.SplitHostPort(r.Host)
		if err != nil {
			log.Println(id, "split host port failed", err)
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}

		serverConn, err := (&net.Dialer{}).DialContext(r.Context(), "tcp", net.JoinHostPort(host, port))
		if err != nil {
			log.Println(id, "dial failed", err)
			http.Error(w, "dial failed", http.StatusServiceUnavailable)
			return
		}
		defer serverConn.Close()
		defer io.Copy(io.Discard, serverConn) // nolint:errcheck

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

		if err := clientConn.SetDeadline(time.Time{}); err != nil {
			log.Println(id, "set deadline failed", err)
			return
		}

		group := errgroup.Group{}
		group.Go(pipe(serverConn, clientConn))
		group.Go(pipe(clientConn, serverConn))

		log.Println(id, "request done", group.Wait())
	})
	log.Fatal(http.ListenAndServe(":8888", handler))
}
