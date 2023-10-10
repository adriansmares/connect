// Copyright © 2023 Adrian-Stefan Mares.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

func removeHopHeaders(h http.Header) http.Header {
	h = h.Clone()
	for _, header := range []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	} {
		h.Del(header)
	}
	return h
}

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

func handleAuthentication(w http.ResponseWriter, r *http.Request, expectedUsernameHash, expectedPasswordHash []byte, requireAuth bool) bool {
	if !requireAuth {
		return true
	}
	username, password, ok := parseBasicAuth(r.Header.Get(proxyAuthorization))
	if !ok {
		return false
	}
	usernameHash, passwordHash := sha3.Sum512([]byte(username)), sha3.Sum512([]byte(password))
	equalUsername := subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash)
	equalPassword := subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash)
	return (equalUsername & equalPassword) == 1
}

func main() {
	dialer := &net.Dialer{}

	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.DialContext = dialer.DialContext
	httpTransport.MaxIdleConnsPerHost = -1
	httpClient := &http.Client{
		Transport: httpTransport,
	}

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

		if !handleAuthentication(w, r, usernameHash[:], passwordHash[:], requireAuth) {
			log.Println(id, "authentication failed")
			w.Header().Add(proxyAuthenticate, "Basic")
			http.Error(w, "authentication required", http.StatusProxyAuthRequired)
			return
		}

		if r.Method != http.MethodConnect {
			defer r.Body.Close()
			defer io.Copy(io.Discard, r.Body) // nolint:errcheck

			req, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
			if err != nil {
				log.Println(id, "create request failed", err)
				http.Error(w, "create request failed", http.StatusBadRequest)
				return
			}
			req.Header = removeHopHeaders(r.Header)

			resp, err := httpClient.Do(req)
			if err != nil {
				log.Println(id, "do request failed", err)
				http.Error(w, "do request failed", http.StatusServiceUnavailable)
				return
			}
			defer resp.Body.Close()
			defer io.Copy(io.Discard, resp.Body) // nolint:errcheck

			for header, values := range removeHopHeaders(resp.Header) {
				for _, value := range values {
					w.Header().Add(header, value)
				}
			}
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body) // nolint:errcheck

			log.Println(id, "request done")
			return
		}

		host, port, err := net.SplitHostPort(r.Host)
		if err != nil {
			log.Println(id, "split host port failed", err)
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}

		serverConn, err := dialer.DialContext(r.Context(), "tcp", net.JoinHostPort(host, port))
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
