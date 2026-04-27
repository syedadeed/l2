package utils

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var symmetricKey = []byte{36, 251, 226, 103, 101, 83, 92, 244, 166, 20, 188, 81, 100, 89, 128, 29, 208, 59, 89, 176, 116, 214, 116, 169, 207, 0, 153, 82, 203, 156, 196, 247}

func GenerateTokenPair(userId string) (accessTokenString string, refreshTokenString string, refreshTokenId uuid.UUID, refreshTokenExpiresAt time.Time, accessTokenExpiresAt time.Time, err error) {
	accessTokenExpiresAt = time.Now().Add(5 * time.Minute)
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "Test",
		Subject:   userId,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(accessTokenExpiresAt),
	})

	accessTokenString, err = accessToken.SignedString(symmetricKey)
	if err != nil {
		return
	}

	refreshTokenId = uuid.New()
	refreshTokenExpiresAt = time.Now().Add(30 * 24 * time.Hour)

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "Test",
		Subject:   userId,
		ID:        refreshTokenId.String(),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(refreshTokenExpiresAt),
	})

	refreshTokenString, err = refreshToken.SignedString(symmetricKey)
	if err != nil {
		return
	}

	return
}
