package middleware

import (
	"errors"
	"net/http"

	"l2/db/repository"
)

type Middleware struct {
	queries *repository.Queries
}

func NewMiddleware(queries *repository.Queries) (*Middleware, error) {
	if queries == nil {
		return nil, errors.New("All fields must be non nil values")
	}
	return &Middleware{queries: queries}, nil
}

func ChainMiddlewares(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}
