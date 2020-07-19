package auth

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

type userCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type tokenResponse struct {
	AccessToken string `json:"accessToken"`
}

// RegisterHandlers ..
func RegisterHandlers(router *mux.Router, service Service) {
	router.HandleFunc("/login", login(service)).Methods(http.MethodPost)

	protectedRouter := router.NewRoute().Subrouter()
	protectedRouter.Use(authRequired)
	protectedRouter.HandleFunc("/refresh-tokens", refreshTokens(service)).Methods(http.MethodGet)
	protectedRouter.HandleFunc("/revoke-tokens", revokeTokens(service)).Methods(http.MethodDelete)
	protectedRouter.HandleFunc("/revoke-all-tokens", revokeAllTokens(service)).Methods(http.MethodDelete)
}

func login(service Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		GUIDFromHeader := r.Header.Get("guid")
		if GUIDFromHeader == "" {
			log.Println("no guid header found")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		var userInput userCredentials
		err := json.NewDecoder(r.Body).Decode(&userInput)
		if err != nil {
			log.Println(err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		tokens, err := service.Login(r.Context(), GUIDFromHeader, userInput.Username, userInput.Password)
		if err != nil {
			log.Println("login error", err)
			switch e := err.(type) {
			case StatusError:
				http.Error(w, http.StatusText(e.Code), e.Code)
				return
			default:
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "refresh-token",
			Value:    tokens.RefreshToken,
			MaxAge:   60 * 24 * 60 * 60, // 60 days
			HttpOnly: true,
		})

		response := tokenResponse{
			AccessToken: tokens.AccessToken,
		}

		err = json.NewEncoder(w).Encode(response)
		if err != nil {
			log.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	}
}

func refreshTokens(service Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authData, ok := r.Context().Value(AuthContextKey).(ContextData)
		if !ok {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		tokens, err := service.RefreshTokens(r.Context(), authData)
		if err != nil {
			log.Println("refresh tokens error:", err)
			switch e := err.(type) {
			case StatusError:
				http.Error(w, http.StatusText(e.Code), e.Code)
			default:
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}

			http.SetCookie(w, &http.Cookie{
				Name:     "refresh-token",
				Value:    tokens.RefreshToken,
				Expires:  time.Now(),
				MaxAge:   0,
				HttpOnly: true,
			})
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "refresh-token",
			Value:    tokens.RefreshToken,
			MaxAge:   60 * 24 * 60 * 60, // 60 days
			HttpOnly: true,
		})

		response := tokenResponse{
			AccessToken: tokens.AccessToken,
		}

		err = json.NewEncoder(w).Encode(response)
		if err != nil {
			log.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	}
}

func revokeTokens(service Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authData, ok := r.Context().Value(AuthContextKey).(ContextData)
		if !ok {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		err := service.RevokeTokens(r.Context(), authData)
		if err != nil {
			log.Println("revoke tokens error:", err)
			switch e := err.(type) {
			case StatusError:
				http.Error(w, http.StatusText(e.Code), e.Code)
				return
			default:
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func revokeAllTokens(service Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authData, ok := r.Context().Value(AuthContextKey).(ContextData)
		if !ok {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		err := service.RevokeAllTokens(r.Context(), authData)
		if err != nil {
			log.Println("revoke all tokens error:", err)
			switch e := err.(type) {
			case StatusError:
				http.Error(w, http.StatusText(e.Code), e.Code)
				return
			default:
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
