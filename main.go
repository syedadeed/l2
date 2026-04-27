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

func chainMiddlewares(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}

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

	mux := http.NewServeMux()
	mux.Handle("POST /signup/start/", http.HandlerFunc(authHandler.SignupStart))
	mux.Handle("POST /signup/finish/", http.HandlerFunc(authHandler.SignupFinish))
	mux.Handle("POST /signin/start/", http.HandlerFunc(authHandler.SigninStart))
	mux.Handle("POST /signin/finish/", http.HandlerFunc(authHandler.SigninFinish))

	http.ListenAndServe(":8080", chainMiddlewares(mux, middleware.Logging))
}
