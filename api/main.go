// srv/geararea/api/main.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

var db *pgxpool.Pool
var jwtKey = []byte("verysecret")

type User struct {
	ID             int       `json:"id"`
	Email          string    `json:"email"`
	Pass           string    `json:"password,omitempty"`
	FullName       *string   `json:"full_name"`
	Bio            *string   `json:"bio"`
	ProfilePicture *string   `json:"profile_picture"`
	Address        *string   `json:"address"`
	AreaCode       *string   `json:"area_code"`
	PayoutType     *string   `json:"payout_type"`
	PayoutName     *string   `json:"payout_name"`
	PayoutNumber   *string   `json:"payout_number"`
	Verified       bool      `json:"verified"`
	CreatedAt      time.Time `json:"created_at"`
}

func main() {
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, "postgres://hotland:rubiksfreak@localhost:5432/geararea?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	db = pool

	mux := http.NewServeMux()

	mux.HandleFunc("POST /signup", signUp)
	mux.HandleFunc("POST /signin", signIn)

	// protected
	mux.Handle("/me", authMiddleware(http.HandlerFunc(meHandler)))
	mux.Handle("/me/verified", authMiddleware(http.HandlerFunc(verifiedHandler)))

	log.Println("API ready on :8080")
	http.ListenAndServe(":8080", mux)
}

//// AUTH MIDDLEWARE ////

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}

		tokenStr := strings.TrimPrefix(auth, "Bearer ")

		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		id, ok := claims["id"].(float64)
		if !ok {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "userID", int(id))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

//// HANDLERS ////

func signUp(w http.ResponseWriter, r *http.Request) {
	var u User
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		http.Error(w, "bad input", http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(u.Pass), 12)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec(context.Background(),
		`INSERT INTO users (email, password_hash) VALUES ($1, $2)`,
		u.Email, string(hash),
	)
	if err != nil {
		http.Error(w, "could not register user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"status":"created"}`))
}

func signIn(w http.ResponseWriter, r *http.Request) {
	var u User
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		http.Error(w, "bad input", http.StatusBadRequest)
		return
	}

	var id int
	var hash string

	err := db.QueryRow(context.Background(),
		`SELECT id, password_hash FROM users WHERE email = $1`,
		u.Email,
	).Scan(&id, &hash)

	if err != nil {
		http.Error(w, "wrong email or password", http.StatusUnauthorized)
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(u.Pass)) != nil {
		http.Error(w, "wrong email or password", http.StatusUnauthorized)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"id": id})
	s, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"token":"` + s + `"}`))
}

//// PROFILE: GET + UPDATE ////

func meHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		getMe(w, r)
	case http.MethodPut:
		updateMe(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func getMe(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(int)

	var u User

	query := `
		SELECT id, email, full_name, bio, profile_picture, 
		       address, area_code, payout_type, payout_name, payout_number, 
		       verified, created_at
		FROM users WHERE id = $1`

	err := db.QueryRow(r.Context(), query, userID).Scan(
		&u.ID, &u.Email, &u.FullName, &u.Bio, &u.ProfilePicture,
		&u.Address, &u.AreaCode, &u.PayoutType, &u.PayoutName, &u.PayoutNumber,
		&u.Verified, &u.CreatedAt,
	)

	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(u)
}

func updateMe(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(int)
	var in User
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad input", http.StatusBadRequest)
		return
	}

	// Dynamic Query Builder
	// We only update fields that are present in the JSON
	setParts := []string{}
	args := []interface{}{}
	argId := 1

	// Helper to reduce repetition
	add := func(col string, val interface{}) {
		setParts = append(setParts, fmt.Sprintf("%s = $%d", col, argId))
		args = append(args, val)
		argId++
	}

	if in.Email != "" {
		add("email", in.Email)
	}
	if in.FullName != nil {
		add("full_name", *in.FullName)
	}
	if in.Bio != nil {
		add("bio", *in.Bio)
	}
	if in.ProfilePicture != nil {
		add("profile_picture", *in.ProfilePicture)
	}
	if in.Address != nil {
		add("address", *in.Address)
	}
	if in.AreaCode != nil {
		add("area_code", *in.AreaCode)
	}
	if in.PayoutType != nil {
		add("payout_type", *in.PayoutType)
	}
	if in.PayoutName != nil {
		add("payout_name", *in.PayoutName)
	}
	if in.PayoutNumber != nil {
		add("payout_number", *in.PayoutNumber)
	}

	// Handle Password separately (hashing)
	if in.Pass != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(in.Pass), 12)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		add("password_hash", string(hash))
	}

	if len(setParts) == 0 {
		w.WriteHeader(http.StatusOK) // Nothing to update
		return
	}

	// Finalize Query: UPDATE users SET ... WHERE id = ...
	query := fmt.Sprintf("UPDATE users SET %s WHERE id = $%d", strings.Join(setParts, ", "), argId)
	args = append(args, userID)

	_, err := db.Exec(r.Context(), query, args...)
	if err != nil {
		// In production, check for unique constraint violations (e.g. email)
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"updated"}`))
}

func verifiedHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(int)

	if r.Method == http.MethodGet {
		var verified bool
		err := db.QueryRow(r.Context(), "SELECT verified FROM users WHERE id=$1", userID).Scan(&verified)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]bool{"verified": verified})
		return
	}

	if r.Method == http.MethodPut {
		var in struct {
			Verified bool `json:"verified"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad input", http.StatusBadRequest)
			return
		}

		_, err := db.Exec(r.Context(), "UPDATE users SET verified=$1 WHERE id=$2", in.Verified, userID)
		if err != nil {
			http.Error(w, "update failed", http.StatusInternalServerError)
			return
		}
		w.Write([]byte(`{"status":"updated"}`))
		return
	}

	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}
