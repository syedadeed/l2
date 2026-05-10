package utils

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

var symmetricKey = []byte{36, 251, 226, 103, 101, 83, 92, 244, 166, 20, 188, 81, 100, 89, 128, 29, 208, 59, 89, 176, 116, 214, 116, 169, 207, 0, 153, 82, 203, 156, 196, 247}

func GenerateAccessToken(userId string) (accessTokenString string, accessTokenExpiresAt time.Time, err error) {
	accessTokenExpiresAt = time.Now().Add(5 * time.Minute)

	accessToken, err := jwt.NewBuilder().
		Issuer("Test").
		Subject(userId).
		IssuedAt(time.Now()).
		Expiration(accessTokenExpiresAt).
		Build()
	if err != nil {
		return
	}

	signedAccessToken, err := jwt.Sign(accessToken, jwt.WithKey(jwa.HS256(), symmetricKey))
	if err != nil {
		return
	}

	accessTokenString = string(signedAccessToken)

	return
}

func VerifyAccessToken(tokenString string) (uuid.UUID, error) {
	accessToken, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithKey(jwa.HS256(), symmetricKey),
		jwt.WithRequiredClaim(jwt.IssuerKey),
		jwt.WithRequiredClaim(jwt.SubjectKey),
		jwt.WithRequiredClaim(jwt.IssuedAtKey),
		jwt.WithRequiredClaim(jwt.ExpirationKey),
		jwt.WithValidate(true),
		jwt.WithIssuer("Test"),
	)
	if err != nil {
		return uuid.Nil, err
	}

	sub, ok := accessToken.Subject()
	if !ok{
		return uuid.Nil, errors.New("missing subject claim")
	}

	userId, err := uuid.Parse(sub)
	if err != nil{
		return uuid.Nil, err
	}

	return userId, nil
}
