// srv/geararea/api/main.go
package main

import (
    "context"
    "encoding/json"
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
    ID        int    `json:"id"`
    Email     string `json:"email"`
    Pass      string `json:"password,omitempty"`
    Verified  bool   `json:"verified"`
    CreatedAt time.Time `json:"created_at"`
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
        http.Error(w, "fail", http.StatusInternalServerError)
        return
    }

    _, err = db.Exec(context.Background(),
        `INSERT INTO users (email, password_hash) VALUES ($1, $2)`,
        u.Email, string(hash),
    )
    if err != nil {
        http.Error(w, "fail", http.StatusBadRequest)
        return
    }

    w.Write([]byte(`{"status":"ok"}`))
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
        http.Error(w, "wrong email or pass", http.StatusUnauthorized)
        return
    }

    if bcrypt.CompareHashAndPassword([]byte(hash), []byte(u.Pass)) != nil {
        http.Error(w, "wrong email or pass", http.StatusUnauthorized)
        return
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"id": id})
    s, err := token.SignedString(jwtKey)
    if err != nil {
        http.Error(w, "fail", http.StatusInternalServerError)
        return
    }

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
    err := db.QueryRow(context.Background(),
        `SELECT id, email, verified, created_at
         FROM users WHERE id = $1`,
        userID,
    ).Scan(&u.ID, &u.Email, &u.Verified, &u.CreatedAt)

    if err != nil {
        http.Error(w, "not found", http.StatusNotFound)
        return
    }

    json.NewEncoder(w).Encode(u)
}

func updateMe(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value("userID").(int)

    var in User
    if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
        http.Error(w, "bad input", http.StatusBadRequest)
        return
    }

    if in.Email != "" {
        _, err := db.Exec(context.Background(),
            `UPDATE users SET email = $1 WHERE id = $2`,
            in.Email, userID,
        )
        if err != nil {
            http.Error(w, "fail", http.StatusBadRequest)
            return
        }
    }

    if in.Pass != "" {
        hash, err := bcrypt.GenerateFromPassword([]byte(in.Pass), 12)
        if err != nil {
            http.Error(w, "fail", http.StatusInternalServerError)
            return
        }

        _, err = db.Exec(context.Background(),
            `UPDATE users SET password_hash = $1 WHERE id = $2`,
            string(hash), userID,
        )
        if err != nil {
            http.Error(w, "fail", http.StatusBadRequest)
            return
        }
    }

    w.Write([]byte(`{"status":"updated"}`))
}
