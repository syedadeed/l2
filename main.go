package main

import (
	"context"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"l2/db/repository"
	"l2/handlers"
	"l2/middleware"
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

	pool, err := pgxpool.New(context.Background(), "postgres://postgres:pg@localhost:5432/postgres")
	if err != nil {
		panic(err)
	}
	defer pool.Close()
	if err := pool.Ping(context.Background()); err != nil {
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

	authHandler, err := handlers.NewAuthHandler(w, pool, repository.New(pool), rdb)
	if err != nil {
		panic(err)
	}

	mdw, err := middleware.NewMiddleware(repository.New(pool))
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.Handle("POST /signup/start/", http.HandlerFunc(authHandler.SignupStart))
	mux.Handle("POST /signup/finish/", http.HandlerFunc(authHandler.SignupFinish))
	mux.Handle("POST /signin/start/", http.HandlerFunc(authHandler.SigninStart))
	mux.Handle("POST /signin/finish/", http.HandlerFunc(authHandler.SigninFinish))
	mux.Handle("POST /signout/", http.HandlerFunc(authHandler.Signout))

	server := &http.Server{
		Addr:              ":8080",
		Handler:           middleware.ChainMiddlewares(mux, mdw.Logging),
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}
}
