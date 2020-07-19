package auth

import (
	"context"
	"log"
	"net/http"
	"strings"

	uuid "github.com/satori/go.uuid"
)

// ContextData ..
type ContextData struct {
	GUID string
	TokensData
}

// TokensData ..
type TokensData struct {
	AccessToken  string
	RefreshToken string
}

type contextKey int

const (
	// AuthContextKey ..
	AuthContextKey contextKey = iota
)

func authRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		GUIDFromHeader, err := uuid.FromString(r.Header.Get("guid"))
		if err != nil {
			log.Println("malformed guid")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		accessTokenFromHeader := strings.Split(r.Header.Get("Authorization"), "Bearer ")
		if len(accessTokenFromHeader) != 2 {
			log.Println("malformed token")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		refreshTokenFromCookie, err := r.Cookie("refresh-token")
		if err != nil {
			log.Println("no refresh cookie found", err)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		authData := ContextData{
			GUID: GUIDFromHeader.String(),
			TokensData: TokensData{
				AccessToken:  accessTokenFromHeader[1],
				RefreshToken: refreshTokenFromCookie.Value,
			},
		}

		ctx := context.WithValue(r.Context(), AuthContextKey, authData)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
