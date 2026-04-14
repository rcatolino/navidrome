package server

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"

	"github.com/deluan/rest"
	"github.com/go-chi/chi/v5"
	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/consts"
	"github.com/navidrome/navidrome/core/auth"
	"github.com/navidrome/navidrome/core/publicurl"
	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/model/id"
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

type UserInfo struct {
	subject  string
	roles    []any
	username string
}

const SESSION_MAX_AGE = 3600
const SESSION_ID_CTX_KEY = "sessionid"

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
		sessionId, exists := r.Context().Value(SESSION_ID_CTX_KEY).(string)
		if !exists {
			log.Error("/authsso/callback: Expected session id key in context is missing")
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
		if !CheckStateToken(sessionId, state) {
			log.Info("Auth callback: Error validating state with session id", "state", state, "sessionId", sessionId)
			w.WriteHeader(401)
			w.Write([]byte("Authentication error\n"))
			return
		}

		token, err := GetIdToken(code, publicurl.PublicURL(r, "/authsso/callback", nil))
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

		userInfo, err := checkClaims(res)
		if err != nil {
			log.Info("Auth callback: error checking token claims", "error", err)
			w.WriteHeader(403)
			w.Write([]byte("Authorization error\n"))
			return
		}

		userRepo := ds.User(r.Context())
		user, err := userRepo.FindByUsername(userInfo.username)
		if user == nil || err != nil {
			log.Info(r, "User not found in local repository", "user", userInfo.username)
			newUser := model.User{
				ID:          id.NewRandom(),
				UserName:    userInfo.username,
				Name:        userInfo.username,
				Email:       "",
				NewPassword: consts.PasswordAutogenPrefix + id.NewRandom(),
				IsAdmin:     slices.Contains(userInfo.roles, "navidrome-admin"), // Make the first user an admin
			}
			err := userRepo.Put(&newUser)
			if err != nil {
				log.Error(r, "Could not create new user", "user", userInfo.username, err)
				w.WriteHeader(500)
				w.Write([]byte("Internal server error\n"))
				return
			}
			user, err = userRepo.FindByUsername(userInfo.username)
			if user == nil || err != nil {
				log.Error(r, "Created user but failed to fetch it", "user", userInfo.username)
				_ = rest.RespondWithError(w, http.StatusInternalServerError, "Unknown error authenticating user. Please try again")
				return
			}
		}

		err = userRepo.UpdateLastLoginAt(user.ID)
		if err != nil {
			log.Error(r, "Could not update LastLoginAt", "user", userInfo.username, err)
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
		sessionId, exists := r.Context().Value(SESSION_ID_CTX_KEY).(string)
		if !exists {
			log.Fatal("OpenID auth bug: sessionId not set. The SessionId middleware should be run before authentication.")
		}
		url := fmt.Sprintf(
			"%s?response_type=code&client_id=%s&scope=openid%%20roles&redirect_uri=%s&state=%s",
			conf.Server.OpenID.AuthorizationURL,
			conf.Server.OpenID.ClientId,
			publicurl.PublicURL(r, "/authsso/callback", nil),
			MakeStateToken(sessionId),
		)

		log.Info("Auth middleware, redirecting to IDP", "url", url)
		http.Redirect(w, r, url, 302)
	}
}

func GetIdToken(code string, redirectUri string) (*TokenResponse, error) {
	// See https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
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

// Similar to the clientUniqueIDMiddleware, but a bit different.
// - not controlled by the client
// - same-site: lax (important to be sent by the UA on 302 redirects from IDP)
func sessionIdMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		log.Debug("SessionId middleware begin")
		s, err := r.Cookie(SESSION_ID_CTX_KEY)
		var sessionId string
		if err != nil {
			// No existing session cookie
			// Create new session
			sessionId = rand.Text()
			log.Debug("No session cookie, creating one", "session_id", sessionId)
			http.SetCookie(w, &http.Cookie{
				Name:     SESSION_ID_CTX_KEY,
				Path:     "/",
				Value:    sessionId,
				MaxAge:   SESSION_MAX_AGE,
				Secure:   conf.Server.TLSKey != "",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
		} else {
			sessionId = s.Value
			log.Debug("Existing session cookie found", "session_id", sessionId)
		}

		ctx = context.WithValue(ctx, SESSION_ID_CTX_KEY, sessionId)
		r = r.WithContext(ctx)
		// Call the next middleware or handler in the chain
		next.ServeHTTP(w, r)
	})
}
