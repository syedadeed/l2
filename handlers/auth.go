package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"l2/db/repository"
)

const signupSessionType = "signup_session"
const signinSessionType = "signin_session"
const passkeySignupCookieName = "passkey_signup_session"
const passkeySigninCookieName = "passkey_signin_session"

type tempUser struct {
	id       []byte
	userName string
	name     string
	creds    []webauthn.Credential
}

func (tu *tempUser) WebAuthnID() []byte                         { return tu.id }
func (tu *tempUser) WebAuthnName() string                       { return tu.userName }
func (tu *tempUser) WebAuthnDisplayName() string                { return tu.name }
func (tu *tempUser) WebAuthnCredentials() []webauthn.Credential { return tu.creds }

func newTempUser() *tempUser {
	id := uuid.New()
	return &tempUser{
		id:       id[:],
		userName: base64.RawURLEncoding.EncodeToString(id[:]),
		name:     "user",
		creds:    nil,
	}
}

type AuthHandler struct {
	webAuthn *webauthn.WebAuthn
	pool     *pgxpool.Pool
	queries  *repository.Queries
	cache    *redis.Client
}

func NewAuthHandler(webAuthn *webauthn.WebAuthn, pool *pgxpool.Pool, queries *repository.Queries, cache *redis.Client) (*AuthHandler, error) {
	if webAuthn == nil || pool == nil || queries == nil || cache == nil {
		return nil, errors.New("All fields must be non nil values")
	}
	return &AuthHandler{webAuthn: webAuthn, pool: pool, queries: queries, cache: cache}, nil
}

func (ah *AuthHandler) SignupStart(w http.ResponseWriter, r *http.Request) {
	options, session, err := ah.webAuthn.BeginMediatedRegistration(
		newTempUser(),
		protocol.MediationDefault,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithExtensions(map[string]any{"credProps": true}),
	)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	sessionBytes, err := json.Marshal(session)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	optionsBytes, err := json.Marshal(options)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	sessionVal := base64.RawURLEncoding.EncodeToString(sessionBytes)

	if err := ah.cache.Set(r.Context(), sessionVal, signupSessionType, time.Until(session.Expires)).Err(); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     passkeySignupCookieName,
		Value:    sessionVal,
		Path:     "/",
		MaxAge:   int(time.Until(session.Expires).Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(optionsBytes)
}

func (ah *AuthHandler) SignupFinish(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(passkeySignupCookieName)
	if err != nil {
		http.Error(w, "Missing session cookie", http.StatusUnauthorized)
		return
	}

	sessionType, err := ah.cache.Get(r.Context(), cookie.Value).Result()
	if err == redis.Nil || sessionType != signupSessionType {
		http.SetCookie(w, &http.Cookie{Name: passkeySignupCookieName, MaxAge: -1, Path: "/"})
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	sessionBytes, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	var session webauthn.SessionData
	if err := json.Unmarshal(sessionBytes, &session); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	cred, err := ah.webAuthn.FinishRegistration(
		&tempUser{
			id:       session.UserID,
			userName: base64.RawURLEncoding.EncodeToString(session.UserID),
			name:     "user",
			creds:    nil,
		},
		session,
		r,
	)
	if err != nil {
		http.Error(w, "Registration failed", http.StatusUnauthorized)
		return
	}

	tx, err := ah.pool.Begin(r.Context())
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(r.Context())

	qtx := ah.queries.WithTx(tx)

	err = qtx.AddUser(r.Context(), repository.AddUserParams{
		ID:        uuid.UUID(session.UserID),
		FirstName: "user",
		LastName:  "user",
		Username:  base64.RawURLEncoding.EncodeToString(session.UserID),
	})
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	err = qtx.AddCredential(r.Context(), repository.AddCredentialParams{
		ID:         cred.ID,
		UserID:     uuid.UUID(session.UserID),
		Credential: *cred,
	})
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	//TODO issue a JWT

	http.SetCookie(w, &http.Cookie{Name: passkeySignupCookieName, MaxAge: -1, Path: "/"})
	ah.cache.Del(r.Context(), cookie.Value)
	w.WriteHeader(http.StatusOK)
}

func (ah *AuthHandler) SigninStart(w http.ResponseWriter, r *http.Request) {
	challenge, session, err := ah.webAuthn.BeginDiscoverableMediatedLogin(protocol.MediationDefault)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	sessionBytes, err := json.Marshal(session)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	challengeBytes, err := json.Marshal(challenge)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	sessionVal := base64.RawURLEncoding.EncodeToString(sessionBytes)

	if err := ah.cache.Set(r.Context(), sessionVal, signinSessionType, time.Until(session.Expires)).Err(); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     passkeySigninCookieName,
		Value:    sessionVal,
		Path:     "/",
		MaxAge:   int(time.Until(session.Expires).Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(challengeBytes)
}

func (ah *AuthHandler) SigninFinish(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(passkeySigninCookieName)
	if err != nil {
		http.Error(w, "Missing session cookie", http.StatusUnauthorized)
		return
	}

	sessionType, err := ah.cache.Get(r.Context(), cookie.Value).Result()
	if err == redis.Nil || sessionType != signinSessionType {
		http.SetCookie(w, &http.Cookie{Name: passkeySigninCookieName, MaxAge: -1, Path: "/"})
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	sessionBytes, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	var session webauthn.SessionData
	if err := json.Unmarshal(sessionBytes, &session); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	lookupUser := func(credId, userId []byte) (webauthn.User, error) {
		exists, err := ah.queries.VerifyCredentialOwner(r.Context(), repository.VerifyCredentialOwnerParams{
			UserID: uuid.UUID(userId),
			CredID: credId,
		})
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, errors.New("Unauthorized")
		}

		creds, err := ah.queries.GetCredentialsByUser(r.Context(), uuid.UUID(userId))
		if err != nil {
			return nil, err
		}

		user, err := ah.queries.GetUser(r.Context(), uuid.UUID(userId))
		if err != nil {
			return nil, err
		}

		return &tempUser{
			id:       user.ID[:],
			userName: user.Username,
			name:     user.FirstName + " " + user.LastName,
			creds:    creds,
		}, nil
	}

	validatedUser, validatedCredential, err := ah.webAuthn.FinishPasskeyLogin(lookupUser, session, r)
	if err != nil {
		http.Error(w, "Login failed", http.StatusUnauthorized)
		return
	}

	err = ah.queries.UpdateCredential(r.Context(), repository.UpdateCredentialParams{
		ID:         validatedCredential.ID,
		Credential: *validatedCredential,
	})
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	//TODO issue a JWT
	_ = validatedUser

	http.SetCookie(w, &http.Cookie{Name: passkeySigninCookieName, MaxAge: -1, Path: "/"})
	ah.cache.Del(r.Context(), cookie.Value)
	w.WriteHeader(http.StatusOK)
}
