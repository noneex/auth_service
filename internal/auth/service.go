package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	uuid "github.com/satori/go.uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

// Service ..
type Service interface {
	Login(ctx context.Context, guid, username, password string) (TokensData, error)
	RefreshTokens(ctx context.Context, authInfo ContextData) (TokensData, error)
	RevokeTokens(ctx context.Context, authInfo ContextData) error
	RevokeAllTokens(ctx context.Context, authInfo ContextData) error
}

// StatusError ..
type StatusError struct {
	Code int
	Err  error
}

func (e StatusError) Error() string {
	return e.Err.Error()
}

type service struct {
	db        DB
	jwtSecret []byte
}

type tokensInfo struct {
	GUID         string    `bson:"guid"`
	Username     string    `bson:"username"`
	RefreshToken string    `bson:"refreshToken"`
	AccessToken  string    `bson:"accessToken"`
	Expires      time.Time `bson:"expires"`
	Created      time.Time `bson:"created"`
}

// DB ..
type DB struct {
	Conn           *mongo.Client
	Name           string
	CollectionName string
}

// Collection ..
func (db DB) Collection() *mongo.Collection {
	return db.Conn.Database(db.Name).Collection(db.CollectionName)
}

var (
	errNoUsername = errors.New("No username found")
	errNoGUID     = errors.New("No guid found")
)

// NewService ..
func NewService(db DB, jwtSecret []byte) Service {
	return service{db: db, jwtSecret: jwtSecret}
}

func (s service) Login(ctx context.Context, guid, username, password string) (TokensData, error) {
	var tokens TokensData

	// dummy check
	if username == "" || password == "" {
		return tokens, StatusError{Code: http.StatusBadRequest, Err: errors.New("unknown username or bad password")}
	}

	accessToken := createAccessJWT(guid, username)
	accessTokenStr, err := accessToken.SignedString(s.jwtSecret)
	if err != nil {
		return tokens, StatusError{Code: http.StatusInternalServerError, Err: fmt.Errorf("signedString error: %s", err)}
	}

	refreshTokenBase64, err := generateRefreshToken()
	if err != nil {
		return tokens, StatusError{Code: http.StatusInternalServerError, Err: fmt.Errorf("generateRefreshToken error: %s", err)}
	}

	tokensCollection := s.db.Collection()
	rti := createTokensInfo(guid, username, accessTokenStr, refreshTokenBase64, nil)
	_, err = tokensCollection.InsertOne(ctx, rti)

	if err != nil {
		return tokens, StatusError{Code: http.StatusInternalServerError, Err: fmt.Errorf("insertOne error: %s", err)}
	}

	tokens = TokensData{
		AccessToken:  accessTokenStr,
		RefreshToken: refreshTokenBase64,
	}

	return tokens, nil
}

func (s service) RefreshTokens(ctx context.Context, authInfo ContextData) (TokensData, error) {
	var tokens TokensData

	accessTokenClaims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(authInfo.AccessToken, accessTokenClaims, func(token *jwt.Token) (interface{}, error) {
		return s.jwtSecret, nil
	})
	if err != nil {
		jwtErr, ok := err.(*jwt.ValidationError)
		if !ok {
			return tokens, StatusError{Code: http.StatusInternalServerError, Err: fmt.Errorf("JWT casting error: %s", err)}
		}
		if jwtErr.Errors != jwt.ValidationErrorExpired {
			return tokens, StatusError{Code: http.StatusInternalServerError, Err: fmt.Errorf("JWT error: %s", err)}
		}
	}

	GUIDFromAccessToken, ok := accessTokenClaims["guid"].(string)
	if !ok {
		return tokens, StatusError{Code: http.StatusUnauthorized, Err: errNoGUID}
	}
	usernameFromAccessToken, ok := accessTokenClaims["username"].(string)
	if !ok {
		return tokens, StatusError{Code: http.StatusUnauthorized, Err: errNoUsername}
	}

	session, err := s.db.Conn.StartSession()
	if err != nil {
		return tokens, StatusError{Code: http.StatusInternalServerError, Err: fmt.Errorf("db startSession error: %s", err)}
	}
	defer session.EndSession(ctx)

	if err = session.StartTransaction(); err != nil {
		return tokens, StatusError{Code: http.StatusInternalServerError, Err: fmt.Errorf("session startTransaction error: %s", err)}
	}

	refreshTokenBase64, err := generateRefreshToken()
	if err != nil {
		return tokens, err
	}

	accessToken := createAccessJWT(GUIDFromAccessToken, usernameFromAccessToken)
	accessTokenStr, err := accessToken.SignedString(s.jwtSecret)

	err = mongo.WithSession(ctx, session, func(sc mongo.SessionContext) error {
		tokensCollection := s.db.Collection()
		deleteResult := tokensCollection.FindOneAndDelete(sc, bson.M{
			"guid":         GUIDFromAccessToken,
			"accessToken":  authInfo.AccessToken,
			"refreshToken": authInfo.RefreshToken,
		})

		if deleteResult.Err() != nil {
			if deleteResult.Err() == mongo.ErrNoDocuments {
				return StatusError{Code: http.StatusUnauthorized, Err: deleteResult.Err()}
			}
			return deleteResult.Err()
		}

		var foundToken tokensInfo
		err = deleteResult.Decode(&foundToken)
		if err != nil {
			return err
		}

		if foundToken.Expires.Before(time.Now()) {
			return StatusError{Code: http.StatusUnauthorized, Err: errors.New("refresh token is expired")}
		}

		rti := createTokensInfo(GUIDFromAccessToken, usernameFromAccessToken, accessTokenStr, refreshTokenBase64, nil)
		if _, err := tokensCollection.InsertOne(sc, rti); err != nil {
			return err
		}

		return session.CommitTransaction(sc)
	})

	tokens = TokensData{
		AccessToken:  accessTokenStr,
		RefreshToken: refreshTokenBase64,
	}

	return tokens, err
}

func (s service) RevokeTokens(ctx context.Context, authInfo ContextData) error {
	tokensCollection := s.db.Collection()
	deleteResult := tokensCollection.FindOneAndDelete(ctx, bson.M{
		"guid":         authInfo.GUID,
		"accessToken":  authInfo.AccessToken,
		"refreshToken": authInfo.RefreshToken,
	})
	fmt.Println("wtf", deleteResult.Err())
	if deleteResult.Err() != nil && deleteResult.Err() != mongo.ErrNoDocuments {
		return deleteResult.Err()
	}
	return nil
}

func (s service) RevokeAllTokens(ctx context.Context, authInfo ContextData) error {
	accessTokenClaims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(authInfo.AccessToken, accessTokenClaims, func(token *jwt.Token) (interface{}, error) {
		return s.jwtSecret, nil
	})
	if err != nil {
		jwtErr, ok := err.(*jwt.ValidationError)
		if !ok {
			return StatusError{Code: http.StatusInternalServerError, Err: fmt.Errorf("JWT casting error: %s", err)}
		}
		if jwtErr.Errors != jwt.ValidationErrorExpired {
			return StatusError{Code: http.StatusInternalServerError, Err: fmt.Errorf("JWT error: %s", err)}
		}
	}

	usernameFromAccessToken, ok := accessTokenClaims["username"].(string)
	if !ok {
		return StatusError{Code: http.StatusUnauthorized, Err: errNoUsername}
	}

	tokensCollection := s.db.Collection()
	_, err = tokensCollection.DeleteMany(ctx, bson.M{
		"username": usernameFromAccessToken,
	})
	if err != nil {
		return StatusError{Code: http.StatusInternalServerError, Err: fmt.Errorf("db DeleteMany error: %s", err)}
	}

	return nil
}

func createAccessJWT(guid, username string) *jwt.Token {
	return jwt.NewWithClaims(jwt.GetSigningMethod(jwt.SigningMethodHS512.Name), jwt.MapClaims{
		"guid":     guid,
		"username": username,
		"exp":      time.Now().Add(30 * time.Minute).Unix(),
	})
}

func createTokensInfo(guid, username, accessToken, refreshToken string, expires *time.Time) tokensInfo {
	expireTime := time.Now().Add(60 * 24 * time.Hour)
	if expires != nil {
		expireTime = *expires
	}

	ti := tokensInfo{
		GUID:         guid,
		Username:     username,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Expires:      expireTime,
		Created:      time.Now(),
	}

	return ti
}

func generateRefreshToken() (string, error) {
	refreshToken := uuid.NewV4()
	refreshTokenHash, err := bcrypt.GenerateFromPassword(refreshToken.Bytes(), 14)
	if err != nil {
		return "", err
	}

	refreshTokenBase64 := base64.StdEncoding.EncodeToString(refreshTokenHash)
	return refreshTokenBase64, nil
}
