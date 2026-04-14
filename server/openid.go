package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/deluan/rest"
	"github.com/go-chi/chi/v5"
	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/consts"
	"github.com/navidrome/navidrome/core/auth"
	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/model/id"
	"github.com/navidrome/navidrome/model/request"
)

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorUri         string `json:"error_uri"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int32  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IdToken      string `json:"id_token"`
}

var _state_key = GetRand128()

func GetRand128() (key [32]byte) {
	rand.Read(key[:])
	return key
}

// 'Relying party' implementation of openid connect 'Authorization Code Flow'
// https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth

func (s *Server) mountOpenidConnectRoutes() chi.Router {
	r := s.router
	if conf.Server.OpenID.Enabled {
		return r.Route(path.Join(conf.Server.BasePath, "/authsso"), func(r chi.Router) {
			log.Warn("Login rate limit is disabled! Consider enabling it to be protected against brute-force attacks")
			r.Get("/login", ssologin())
			r.Get("/callback", ssocallback(s.ds))
		})
	} else {
		return r
	}
}

func ssocallback(ds model.DataStore) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		values := r.URL.Query()
		clientUniqueId, exists := request.ClientUniqueIdFrom(r.Context())
		if !exists {
			log.Error("/authsso/callback: Expected client id key in context is missing")
			http.Redirect(w, r, "/", 302)
			return
		}

		// See https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint
		if values.Has("error") {
			w.WriteHeader(400)
			fmt.Fprintf(w, "Authentication error (%s) %s\n", values.Get("error"), values.Get("error_description"))
			return
		}

		if !values.Has("session_state") || !values.Has("code") {
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized\n"))
			return
		}

		// See RFC 6749 Sections 4.1.2 and 10.12.
		session_state := values.Get("session_state")
		state := values.Get("state")
		code := values.Get("code")
		log.Debug("Auth callback url.", "state", state, "session_state", session_state, "code", code)
		if !CheckStateToken(clientUniqueId, state) {
			log.Info("Auth callback: Error validating state with client id", "state", state, "clientId", clientUniqueId)
			w.WriteHeader(401)
			w.Write([]byte("Authentication error\n"))
			return
		}

		// TODO: remove passing of qp
		qp := values.Get("qp")
		token, err := GetIdToken(code, qp)
		if err != nil {
			log.Warn("Auth callback: GetIdToken failed", "error", err)
			w.WriteHeader(401)
			w.Write([]byte("Authentication error\n"))
			return
		}

		res, err := validateToken(token.IdToken)
		if err != nil {
			log.Info("Auth callback: error validating id token", "error", err)
			w.WriteHeader(401)
			w.Write([]byte("Authentication error\n"))
			return
		}

		_, username, err := checkClaims(res)
		if err != nil {
			log.Info("Auth callback: error checking token claims", "error", err)
			w.WriteHeader(403)
			w.Write([]byte("Authorization error\n"))
			return
		}

		userRepo := ds.User(r.Context())
		user, err := userRepo.FindByUsername(username)
		if user == nil || err != nil {
			log.Info(r, "User not found in local repository", "user", username)
			// Check if this is the first user being created
			count, _ := userRepo.CountAll()
			isFirstUser := count == 0

			newUser := model.User{
				ID:          id.NewRandom(),
				UserName:    username,
				Name:        username,
				Email:       "",
				NewPassword: consts.PasswordAutogenPrefix + id.NewRandom(),
				IsAdmin:     isFirstUser, // Make the first user an admin
			}
			err := userRepo.Put(&newUser)
			if err != nil {
				log.Error(r, "Could not create new user", "user", username, err)
				w.WriteHeader(500)
				w.Write([]byte("Internal server error\n"))
				return
			}
			user, err = userRepo.FindByUsernameWithPassword(username)
			if user == nil || err != nil {
				log.Error(r, "Created user but failed to fetch it", "user", username)
				_ = rest.RespondWithError(w, http.StatusInternalServerError, "Unknown error authenticating user. Please try again")
				return
			}
		}

		err = userRepo.UpdateLastLoginAt(user.ID)
		if err != nil {
			log.Error(r, "Could not update LastLoginAt", "user", username, err)
			_ = rest.RespondWithError(w, http.StatusInternalServerError, "Unknown error authenticating user. Please try again")
			return
		}

		tokenString, err := auth.CreateToken(user)
		if err != nil {
			_ = rest.RespondWithError(w, http.StatusInternalServerError, "Unknown error authenticating user. Please try again")
			return
		}
		payload := buildAuthPayload(user)
		payload["token"] = tokenString
		_ = rest.RespondWithJSON(w, http.StatusOK, payload)
	}
}

func ssologin() func(w http.ResponseWriter, r *http.Request) {
	// Triggers an authentication flow following https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
	return func(w http.ResponseWriter, r *http.Request) {
		clientUniqueId, exists := request.ClientUniqueIdFrom(r.Context())
		if !exists {
			log.Fatal("OpenID auth bug: clientUniqueId not set. The ClientUniqueId middleware should be run before authentication.")
		}
		queryParams := base64.URLEncoding.EncodeToString([]byte(r.URL.Query().Encode()))
		url := fmt.Sprintf(
			"%s?response_type=code&client_id=%s&scope=openid%%20roles&redirect_uri=%s/auth/callback%%3fqp=%s&state=%s",
			conf.Server.OpenID.AuthorizationURL,
			conf.Server.OpenID.ClientId,
			conf.Server.BaseURL,
			queryParams,
			MakeStateToken(clientUniqueId),
		)

		log.Info("Auth middleware, redirecting to IDP", "url", url)
		http.Redirect(w, r, url, 302)
	}
}

func GetIdToken(code string, qp string) (*TokenResponse, error) {
	// See https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
	redirectUri := fmt.Sprintf("%s/auth_callback?qp=%s", conf.Server.BaseURL, qp)
	tokenUrlBasicAuth := strings.Replace(
		conf.Server.OpenID.TokenURL,
		"https://", fmt.Sprintf("https://%s:%s@", conf.Server.OpenID.ClientId, conf.Server.OpenID.ClientSecret),
		1)

	resp, err := http.PostForm(tokenUrlBasicAuth, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectUri},
	})

	if err != nil {
		return nil, err
	}

	switch resp.StatusCode {
	case 200:
		var token TokenResponse
		defer resp.Body.Close()
		if err = json.NewDecoder(resp.Body).Decode(&token); err != nil {
			return nil, err
		}

		if !strings.EqualFold(token.TokenType, "Bearer") {
			return nil, fmt.Errorf("unexpected token type '%s'", token.TokenType)
		}

		return &token, nil
	case 400:
		var error ErrorResponse
		defer resp.Body.Close()
		if err = json.NewDecoder(resp.Body).Decode(&error); err != nil {
			return nil, err
		}

		log.Warn("Auth callback: Got invalid request error from token endpoint", "error", error.Error, "errorDescription", error.ErrorDescription, "errorUri", error.ErrorUri)
		return nil, errors.New(error.Error)
	}

	return nil, fmt.Errorf("unexpected response code %d", resp.StatusCode)
}
