package middleware

import (
	"errors"

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
