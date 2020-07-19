package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/noneex/auth_service/internal/auth"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println(err)
	}

	log.Println("Starting server ..")
	if err := run(); err != nil {
		log.Fatalln(err)
	}
}

func run() error {
	var (
		port, _   = strconv.Atoi(env("PORT", "3000"))
		DBURL     = env("DATABASE_URL", "mongodb://localhost:27017/auth")
		jwtSecret = env("JWT_SECRET", "exampleJWTSecretForTest")
	)

	flag.IntVar(&port, "port", port, "Port in which this server will run")
	flag.StringVar(&jwtSecret, "jwtSecret", jwtSecret, "String in which jwt will be signed")
	flag.StringVar(&DBURL, "db", DBURL, "URL for database connection")
	flag.Parse()

	dbCtx := context.Background()
	dbClient, err := mongo.Connect(dbCtx, options.Client().ApplyURI(DBURL))
	if err != nil {
		return fmt.Errorf("could not connect to db: %w", err)
	}
	defer dbClient.Disconnect(dbCtx)

	if err = dbClient.Ping(dbCtx, nil); err != nil {
		return fmt.Errorf("could not ping to db: %w", err)
	}

	hs := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: buildHandler(dbClient, []byte(jwtSecret)),
	}

	return hs.ListenAndServe()
}

func buildHandler(dbConn *mongo.Client, jwtSecret []byte) http.Handler {
	router := mux.NewRouter()
	v1Route := router.PathPrefix("/v1").Subrouter()
	dbInfo := auth.DB{
		Conn:           dbConn,
		Name:           "auth",
		CollectionName: "tokens",
	}
	auth.RegisterHandlers(v1Route, auth.NewService(dbInfo, jwtSecret))

	h := cors.Default().Handler(router)
	return h
}

func env(key, fallback string) string {
	s, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	return s
}
