package main

import (
	"context"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/redis/go-redis/v9"

	"l2/handlers"
)

func main() {
	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})
	defer rdb.Close()
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		panic(err)
	}

	w, err := webauthn.New(&webauthn.Config{
		RPID:          "localhost",
		RPDisplayName: "Test",
		RPOrigins:     []string{"http://localhost:8080"},
		Timeouts: webauthn.TimeoutsConfig{
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    30 * time.Second,
				TimeoutUVD: 30 * time.Second,
			},
			Login: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    30 * time.Second,
				TimeoutUVD: 30 * time.Second,
			},
		},
	})
	if err != nil {
		panic(err)
	}

	authHandler, err := handlers.NewAuthHandler(w, rdb)
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /signup/start", authHandler.SignupStart)
	mux.HandleFunc("POST /signup/finish", authHandler.SignupFinish)

	http.ListenAndServe(":8080", mux)
}
