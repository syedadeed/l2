package middleware

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"l2/db/repository"
	"l2/utils"
)

const AccessTokenCookieName = "access_token"
const RefreshTokenCookieName = "refresh_token"

func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessCookies := r.CookiesNamed(AccessTokenCookieName)
		if len(accessCookies) > 1 {
			http.Error(w, "Multiple access token cookies provided", http.StatusBadRequest)
			return
		}

		fallback := func() error {
			refreshCookies := r.CookiesNamed(RefreshTokenCookieName)
			if len(refreshCookies) > 1 {
				http.Error(w, "Multiple refresh token cookies provided", http.StatusBadRequest)
				return errors.New("Multiple refresh token cookies provided")
			}
			if len(refreshCookies) == 0 {
				http.SetCookie(w, &http.Cookie{Name: AccessTokenCookieName, MaxAge: -1, Path: "/"})
				http.Error(w, "No refresh token cookie provided", http.StatusUnauthorized)
				return errors.New("No refresh token cookie provided")
			}

			sessionId, err := uuid.Parse(refreshCookies[0].Value)
			if err != nil {
				http.SetCookie(w, &http.Cookie{Name: AccessTokenCookieName, MaxAge: -1, Path: "/"})
				http.SetCookie(w, &http.Cookie{Name: RefreshTokenCookieName, MaxAge: -1, Path: "/"})
				http.Error(w, "Invalid refresh token cookie provided", http.StatusUnauthorized)
				return errors.New("Invalid refresh token cookie provided")
			}

			session, err := m.queries.ConsumeSessionById(r.Context(), sessionId)
			if errors.Is(err, pgx.ErrNoRows) {
				session, err := m.queries.GetSupersededSessionById(r.Context(), sessionId)
				if err != nil {
					http.SetCookie(w, &http.Cookie{Name: AccessTokenCookieName, MaxAge: -1, Path: "/"})
					http.SetCookie(w, &http.Cookie{Name: RefreshTokenCookieName, MaxAge: -1, Path: "/"})
					http.Error(w, "Invalid refresh token cookie provided", http.StatusUnauthorized)
					return errors.New("Invalid refresh token cookie provided")
				}
				r = r.WithContext(context.WithValue(r.Context(), "userId", session.UserID.String()))
				return nil
			} else if err != nil {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return errors.New("Internal server error")
			}

			newAccessTokenString, newAccessTokenExpiresAt, err := utils.GenerateAccessToken(session.UserID.String())
			if err != nil {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return errors.New("Internal server error")
			}

			newRefreshTokenId, newRefreshTokenExpiresAt := uuid.New(), time.Now().Add(30*24*time.Hour)

			err = m.queries.AddSession(r.Context(), repository.AddSessionParams{
				SessionID: newRefreshTokenId,
				UserID:    session.UserID,
				ExpiresAt: newRefreshTokenExpiresAt,
			})
			if err != nil {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return errors.New("Internal server error")
			}

			http.SetCookie(w, &http.Cookie{
				Name:     AccessTokenCookieName,
				Value:    newAccessTokenString,
				Path:     "/",
				MaxAge:   int(time.Until(newAccessTokenExpiresAt).Seconds()),
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
			})
			http.SetCookie(w, &http.Cookie{
				Name:     RefreshTokenCookieName,
				Value:    newRefreshTokenId.String(),
				Path:     "/",
				MaxAge:   int(time.Until(newRefreshTokenExpiresAt).Seconds()),
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
			})

			r = r.WithContext(context.WithValue(r.Context(), "userId", session.UserID.String()))
			return nil
		}

		if len(accessCookies) == 0 {
			if err := fallback(); err != nil {
				return
			} else {
				next.ServeHTTP(w, r)
				return
			}
		}

		if userId, err := utils.VerifyAccessToken(accessCookies[0].Value); err != nil {
			if err := fallback(); err != nil {
				return
			}
		} else {
			r = r.WithContext(context.WithValue(r.Context(), "userId", userId))
		}
		next.ServeHTTP(w, r)
	})
}
