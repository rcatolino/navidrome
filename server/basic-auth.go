package server

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/model"
)

func UsernameFromBasicAuth(r *http.Request, ds model.DataStore) string {
	basicAuthHeader := r.Header.Get("Authorization")
	if basicAuthHeader == "" {
		log.Debug(r, "Basic auth: No authorization header")
		return ""
	}

	parts := strings.SplitN(basicAuthHeader, " ", 2)
	if parts[0] != "Basic" || len(parts) != 2 {
		log.Debug(r, "Basic auth: Authorization doesn't match basic auth format")
		return ""
	}

	userpass, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		log.Warn(r, "Basic auth: Authorization header found, but base64 encoding is invalid")
		return ""
	}

	userpassparts := strings.SplitN(string(userpass), ":", 2)
	if len(userpassparts) != 2 {
		log.Warn(r, "Basic auth: Authorization header found, but with invalid format")
		return ""
	}

	user, err := validateLogin(ds.User(r.Context()), userpassparts[0], userpassparts[1])
	if err != nil {
		log.Warn(r, "Basic auth: Error while validating user/password from Basic Auth", "error", err)
		return ""
	}
	if user == nil {
		log.Warn(r, "Basic auth: Authorization header found, but with invalid user/password")
		return ""
	}
	log.Trace(r, "Found username basic auth header", "username", user.UserName)
	return user.UserName
}


