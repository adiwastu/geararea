// srv/geararea/api/main.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

var db *pgxpool.Pool
var jwtKey = []byte("verysecret")
var komshipAPIKey = os.Getenv("KOMSHIP_API_KEY")

type contextKey string

const userIDKey contextKey = "userID"

type User struct {
	ID             int     `json:"id"`
	Email          string  `json:"email"`
	Pass           string  `json:"password,omitempty"`
	Username       string  `json:"username"`
	FullName       *string `json:"full_name"`
	Bio            *string `json:"bio"`
	ProfilePicture *string `json:"profile_picture"`

	// Updated Location Fields
	Address    *string `json:"address"` // Street details (Jalan, RT/RW)
	LocationID *int    `json:"location_id"`
	Province   *string `json:"province"`
	City       *string `json:"city"`
	District   *string `json:"district"`
	PostalCode *string `json:"postal_code"`

	PayoutType   *string   `json:"payout_type"`
	PayoutName   *string   `json:"payout_name"`
	PayoutNumber *string   `json:"payout_number"`
	Verified     bool      `json:"verified"`
	CreatedAt    time.Time `json:"created_at"`
}

type Product struct {
	ID          int64      `json:"id"`
	UserID      int        `json:"user_id"`
	Title       string     `json:"title"`
	Description *string    `json:"description"`
	Category    string     `json:"category"`
	Brand       *string    `json:"brand"`
	Price       int        `json:"price"`
	Condition   string     `json:"condition"`
	Photos      []string   `json:"photos"`
	LengthCM    *int       `json:"length_cm"`
	WidthCM     *int       `json:"width_cm"`
	HeightCM    *int       `json:"height_cm"`
	WeightGram  *int       `json:"weight_grams"`
	IsSold      bool       `json:"is_sold"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `json:"deleted_at"`
}

type CartItem struct {
	Product Product `json:"product"`
}

// CartGroup is for the JSON response: grouped by seller
type CartGroup struct {
	SellerID   int       `json:"seller_id"`
	SellerName string    `json:"seller_name"`
	Items      []Product `json:"items"`
}

type Order struct {
	ID              int       `json:"id"`
	BuyerID         int       `json:"buyer_id"`
	SellerID        int       `json:"seller_id"`
	Status          string    `json:"status"`
	TotalPrice      int       `json:"total_price"`
	ShippingCost    int       `json:"shipping_cost"`
	AppFee          int       `json:"app_fee"`
	GrandTotal      int       `json:"grand_total"`
	ShippingAddress string    `json:"shipping_address"`
	CreatedAt       time.Time `json:"created_at"`
	// We can add payment details here if needed for frontend
}

type SearchResponse struct {
	Users    []UserPreview    `json:"users"`
	Products []ProductPreview `json:"products"`
}

type UserPreview struct {
	ID             int     `json:"id"`
	FullName       string  `json:"full_name"`
	ProfilePicture *string `json:"profile_picture"`
	Location       *string `json:"location,omitempty"` // District/City
}

type ProductPreview struct {
	ID         int     `json:"id"`
	Title      string  `json:"title"`
	Price      int     `json:"price"`
	Condition  string  `json:"condition"`
	Thumbnail  *string `json:"thumbnail"` // First photo
	SellerName string  `json:"seller_name"`
}

type OrderPreview struct {
	ID             int       `json:"id"`
	Status         string    `json:"status"`
	GrandTotal     int       `json:"grand_total"`
	CreatedAt      time.Time `json:"created_at"`
	Counterparty   string    `json:"counterparty"` // Seller Name (if buying) or Buyer Name (if selling)
	FirstItemTitle string    `json:"first_item_title"`
	FirstItemPhoto *string   `json:"first_item_photo"`
	TotalItems     int       `json:"total_items"`
}

type OrderDetail struct {
	ID              int         `json:"id"`
	Status          string      `json:"status"`
	BuyerName       string      `json:"buyer_name"`
	SellerName      string      `json:"seller_name"`
	ShippingAddress string      `json:"shipping_address"`
	TrackingNumber  *string     `json:"tracking_number"`
	GrandTotal      int         `json:"grand_total"`
	ShippingCost    int         `json:"shipping_cost"`
	CreatedAt       time.Time   `json:"created_at"`
	Items           []OrderItem `json:"items"`
}

type OrderItem struct {
	ProductID int     `json:"product_id"`
	Title     string  `json:"title"`
	Price     int     `json:"price"`
	Photo     *string `json:"photo"`
}

type ShopProfile struct {
	ID             int              `json:"id"`
	Username       string           `json:"username"`
	FullName       string           `json:"full_name"`
	ProfilePicture *string          `json:"profile_picture"`
	Location       *string          `json:"location"` // City/District
	JoinedAt       time.Time        `json:"joined_at"`
	Inventory      []ProductPreview `json:"inventory"`
}

var reservedUsernames = map[string]bool{
	// Auth & Account
	"login": true, "signin": true, "signup": true, "register": true, "logout": true,
	"password": true, "account": true, "settings": true, "profile": true, "dashboard": true,
	"admin": true, "root": true, "superuser": true, "staff": true, "moderator": true,

	// Commerce & App Structure
	"cart": true, "checkout": true, "orders": true, "invoices": true,
	"billing": true, "subscription": true, "payment": true, "shipping": true,
	"shop": true, "store": true, "marketplace": true, "search": true,
	"categories": true, "products": true, "items": true, "api": true,

	// Content & Legal
	"about": true, "contact": true, "blog": true, "news": true, "press": true,
	"terms": true, "privacy": true, "legal": true, "faq": true, "help": true,
	"support": true, "status": true, "jobs": true, "careers": true,

	// Technical
	"static": true, "assets": true, "public": true, "images": true, "css": true, "js": true,
	"www": true, "http": true, "https": true, "null": true, "undefined": true,
}

func main() {
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, "postgres://hotland:rubiksfreak@localhost:5432/geararea?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	db = pool

	initUploader()

	mux := http.NewServeMux()

	// Auth
	mux.HandleFunc("POST /signup", signUp)
	mux.HandleFunc("POST /signin", signIn)

	// Me
	mux.Handle("/me", authMiddleware(http.HandlerFunc(meHandler)))
	mux.Handle("/me/verified", authMiddleware(http.HandlerFunc(verifiedHandler)))

	// Public list and detail
	mux.Handle("GET /products", http.HandlerFunc(productsListHandler))
	mux.Handle("GET /products/{id}", http.HandlerFunc(productDetailHandler))

	// Auth required create, update, delete
	mux.Handle("POST /products", authMiddleware(http.HandlerFunc(productsCreateHandler)))
	mux.Handle("PUT /products/{id}", authMiddleware(http.HandlerFunc(productUpdateHandler)))
	mux.Handle("DELETE /products/{id}", authMiddleware(http.HandlerFunc(productDeleteHandler)))
	mux.Handle("DELETE /products/{id}/hard", authMiddleware(http.HandlerFunc(productHardDeleteHandler)))

	// Cart
	mux.Handle("GET /cart", authMiddleware(http.HandlerFunc(cartListHandler)))
	mux.Handle("POST /cart", authMiddleware(http.HandlerFunc(cartAddHandler)))
	mux.Handle("DELETE /cart/{productID}", authMiddleware(http.HandlerFunc(cartRemoveHandler)))

	// Orders
	mux.Handle("POST /checkout", authMiddleware(http.HandlerFunc(checkoutHandler)))
	mux.Handle("POST /orders/{id}/cancel", authMiddleware(http.HandlerFunc(orderCancelHandler)))

	// Media upload
	mux.Handle("POST /media/upload", authMiddleware(http.HandlerFunc(uploadHandler)))

	// Area search
	mux.Handle("GET /locations/search", authMiddleware(http.HandlerFunc(searchLocationHandler)))

	// Shipping calculator
	mux.Handle("POST /cart/shipping", authMiddleware(http.HandlerFunc(calculateShippingHandler)))

	// Search
	mux.Handle("GET /search", http.HandlerFunc(searchHandler))

	// Order History
	mux.Handle("GET /orders/buying", authMiddleware(http.HandlerFunc(listBuyingHandler)))
	mux.Handle("GET /orders/selling", authMiddleware(http.HandlerFunc(listSellingHandler)))
	mux.Handle("GET /orders/", authMiddleware(http.HandlerFunc(orderDetailHandler)))

	// Storefronts
	mux.Handle("GET /shops/", http.HandlerFunc(shopHandler))

	go StartJanitor(db)

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

		ctx := context.WithValue(r.Context(), userIDKey, int(id))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

//// HANDLERS ////

func isValidUsername(u string) error {
	u = strings.ToLower(u)

	// 1. Length Check
	if len(u) < 3 {
		return fmt.Errorf("username too short (min 3 chars)")
	}
	if len(u) > 30 {
		return fmt.Errorf("username too long (max 30 chars)")
	}

	// 2. Format Check (Alphanumeric + Underscore only)
	// Regex: ^[a-z0-9_]+$
	validRegex := regexp.MustCompile(`^[a-z0-9_]+$`)
	if !validRegex.MatchString(u) {
		return fmt.Errorf("username can only contain letters, numbers, and underscores")
	}

	// 3. Blacklist Check
	if reservedUsernames[u] {
		return fmt.Errorf("this username is reserved")
	}

	return nil
}

func signUp(w http.ResponseWriter, r *http.Request) {
	var u User
	// 1. Decode JSON
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		http.Error(w, "bad input", http.StatusBadRequest)
		return
	}

	// 2. VALIDATE USERNAME (The new logic)
	// We enforce lowercase here immediately
	u.Username = strings.ToLower(u.Username)

	if err := isValidUsername(u.Username); err != nil {
		// Return the specific validation error (e.g. "username taken", "too short")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 3. Hash Password
	hash, err := bcrypt.GenerateFromPassword([]byte(u.Pass), 12)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// 4. Insert into DB (Added 'username')
	var newID int
	err = db.QueryRow(context.Background(),
		`INSERT INTO users (email, password_hash, username) VALUES ($1, $2, $3) RETURNING id`,
		u.Email, string(hash), u.Username,
	).Scan(&newID)

	// 5. Handle Constraints (Duplicates)
	if err != nil {
		if strings.Contains(err.Error(), "users_username_key") {
			http.Error(w, "username already taken", http.StatusConflict)
			return
		}
		if strings.Contains(err.Error(), "users_email_key") {
			http.Error(w, "email already registered", http.StatusConflict)
			return
		}
		log.Printf("Signup Error: %v", err)
		http.Error(w, "could not register user", http.StatusInternalServerError)
		return
	}

	// 6. Success
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	// We return the ID now, it's helpful for the frontend
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "created",
		"id":     newID,
	})
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

//// ME: GET + UPDATE ////

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
	userID := r.Context().Value(userIDKey).(int)

	var u User

	// Updated Query
	query := `
        SELECT id, email, full_name, bio, profile_picture, 
               address, location_id, province, city, district, postal_code,
               payout_type, payout_name, payout_number, 
               verified, created_at
        FROM users WHERE id = $1`

	err := db.QueryRow(r.Context(), query, userID).Scan(
		&u.ID, &u.Email, &u.FullName, &u.Bio, &u.ProfilePicture,
		&u.Address, &u.LocationID, &u.Province, &u.City, &u.District, &u.PostalCode,
		&u.PayoutType, &u.PayoutName, &u.PayoutNumber,
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
	userID := r.Context().Value(userIDKey).(int)
	var in User
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad input", http.StatusBadRequest)
		return
	}

	setParts := []string{}
	args := []interface{}{}
	argId := 1

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

	// Address & Location Updates
	if in.Address != nil {
		add("address", *in.Address)
	}
	if in.LocationID != nil {
		add("location_id", *in.LocationID)
	}
	if in.Province != nil {
		add("province", *in.Province)
	}
	if in.City != nil {
		add("city", *in.City)
	}
	if in.District != nil {
		add("district", *in.District)
	}
	if in.PostalCode != nil {
		add("postal_code", *in.PostalCode)
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

	if in.Pass != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(in.Pass), 12)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		add("password_hash", string(hash))
	}

	if len(setParts) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}

	query := fmt.Sprintf("UPDATE users SET %s WHERE id = $%d", strings.Join(setParts, ", "), argId)
	args = append(args, userID)

	_, err := db.Exec(r.Context(), query, args...)
	if err != nil {
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"updated"}`))
}

func verifiedHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(userIDKey).(int)

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

//// PRODUCTS: GET + POST + PUT ////

func productsListHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	page := 1
	limit := 20

	if p := r.URL.Query().Get("page"); p != "" {
		fmt.Sscanf(p, "%d", &page)
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}

	if page < 1 {
		page = 1
	}

	offset := (page - 1) * limit

	rows, err := db.Query(
		r.Context(),
		`SELECT id, user_id, title, description, category, brand, price, condition, photos,
		        length_cm, width_cm, height_cm, weight_grams, is_sold,
		        created_at, updated_at
		 FROM products
         WHERE deleted_at IS NULL
		 ORDER BY created_at DESC
		 LIMIT $1 OFFSET $2`, limit, offset,
	)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	list := []Product{}

	for rows.Next() {
		var p Product
		err := rows.Scan(
			&p.ID, &p.UserID, &p.Title, &p.Description, &p.Category,
			&p.Brand, &p.Price, &p.Condition, &p.Photos,
			&p.LengthCM, &p.WidthCM, &p.HeightCM, &p.WeightGram,
			&p.IsSold, &p.CreatedAt, &p.UpdatedAt,
		)
		if err != nil {
			http.Error(w, "scan failed", http.StatusInternalServerError)
			return
		}
		list = append(list, p)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func getProduct(w http.ResponseWriter, r *http.Request, id int64) {
	var p Product
	err := db.QueryRow(
		r.Context(),
		`SELECT id, user_id, title, description, category, brand, price, condition, photos,
		        length_cm, width_cm, height_cm, weight_grams, is_sold,
		        created_at, updated_at
		 FROM products WHERE id = $1 AND deleted_at IS NULL`,
		id,
	).Scan(
		&p.ID, &p.UserID, &p.Title, &p.Description, &p.Category,
		&p.Brand, &p.Price, &p.Condition, &p.Photos,
		&p.LengthCM, &p.WidthCM, &p.HeightCM, &p.WeightGram,
		&p.IsSold, &p.CreatedAt, &p.UpdatedAt,
	)

	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(p)
}

func updateProduct(w http.ResponseWriter, r *http.Request, id int64) {
	userID := r.Context().Value(userIDKey).(int)

	var owner int
	err := db.QueryRow(r.Context(), "SELECT user_id FROM products WHERE id=$1 AND deleted_at IS NULL", id).Scan(&owner)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if owner != userID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var in Product
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad input", http.StatusBadRequest)
		return
	}

	set := []string{}
	args := []interface{}{}
	arg := 1

	add := func(col string, v interface{}) {
		set = append(set, fmt.Sprintf("%s=$%d", col, arg))
		args = append(args, v)
		arg++
	}

	if in.Title != "" {
		add("title", in.Title)
	}
	if in.Description != nil {
		add("description", in.Description)
	}
	if in.Category != "" {
		add("category", in.Category)
	}
	if in.Brand != nil {
		add("brand", in.Brand)
	}
	if in.Price != 0 {
		add("price", in.Price)
	}
	if in.Condition != "" {
		add("condition", in.Condition)
	}
	if in.Photos != nil {
		add("photos", in.Photos)
	}
	if in.LengthCM != nil {
		add("length_cm", in.LengthCM)
	}
	if in.WidthCM != nil {
		add("width_cm", in.WidthCM)
	}
	if in.HeightCM != nil {
		add("height_cm", in.HeightCM)
	}
	if in.WeightGram != nil {
		add("weight_grams", in.WeightGram)
	}
	if in.IsSold {
		add("is_sold", in.IsSold)
	}

	if len(set) == 0 {
		json.NewEncoder(w).Encode(map[string]string{"status": "no changes"})
		return
	}

	query := fmt.Sprintf(
		"UPDATE products SET %s, updated_at = now() WHERE id = $%d AND deleted_at IS NULL",
		strings.Join(set, ", "),
		arg,
	)

	args = append(args, id)

	_, err = db.Exec(r.Context(), query, args...)
	if err != nil {
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}

func productsCreateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Context().Value(userIDKey).(int)

	var in Product
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad input", http.StatusBadRequest)
		return
	}

	var newID int64

	err := db.QueryRow(
		r.Context(),
		`INSERT INTO products 
		 (user_id, title, description, category, brand, price, condition, photos,
		  length_cm, width_cm, height_cm, weight_grams)
		 VALUES
		 ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		 RETURNING id`,
		userID, in.Title, in.Description, in.Category, in.Brand, in.Price, in.Condition,
		in.Photos, in.LengthCM, in.WidthCM, in.HeightCM, in.WeightGram,
	).Scan(&newID)

	if err != nil {
		http.Error(w, "insert failed", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]int64{"id": newID})
}

//// PRODUCTS: GET + POST + PUT ////

// GET /products/{id}
func productDetailHandler(w http.ResponseWriter, r *http.Request) {
	// FIX: Use PathValue (Go 1.22+)
	idStr := r.PathValue("id")
	var productID int64
	fmt.Sscanf(idStr, "%d", &productID)

	// Logic extracted from getProduct helper
	var p Product
	err := db.QueryRow(
		r.Context(),
		`SELECT id, user_id, title, description, category, brand, price, condition, photos,
                length_cm, width_cm, height_cm, weight_grams, is_sold,
                created_at, updated_at
         FROM products WHERE id = $1 AND deleted_at IS NULL`,
		productID,
	).Scan(
		&p.ID, &p.UserID, &p.Title, &p.Description, &p.Category,
		&p.Brand, &p.Price, &p.Condition, &p.Photos,
		&p.LengthCM, &p.WidthCM, &p.HeightCM, &p.WeightGram,
		&p.IsSold, &p.CreatedAt, &p.UpdatedAt,
	)

	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(p)
}

// PUT /products/{id}
// FIX: Renamed from updateProduct and fixed signature to (w, r)
func productUpdateHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(userIDKey).(int)

	// FIX: Parse ID from path
	idStr := r.PathValue("id")
	var id int64
	fmt.Sscanf(idStr, "%d", &id)

	var owner int
	err := db.QueryRow(r.Context(), "SELECT user_id FROM products WHERE id=$1 AND deleted_at IS NULL", id).Scan(&owner)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if owner != userID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// FIX: Use a local struct or map to handle Partial JSON updates correctly.
	// This example keeps your logic but notes that 'IsSold' cannot be set to false via JSON 'false'.
	var in Product
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad input", http.StatusBadRequest)
		return
	}

	set := []string{}
	args := []interface{}{}
	arg := 1

	add := func(col string, v interface{}) {
		set = append(set, fmt.Sprintf("%s=$%d", col, arg))
		args = append(args, v)
		arg++
	}

	if in.Title != "" {
		add("title", in.Title)
	}
	if in.Description != nil {
		add("description", in.Description)
	}
	if in.Category != "" {
		add("category", in.Category)
	}
	if in.Brand != nil {
		add("brand", in.Brand)
	}
	if in.Price != 0 {
		add("price", in.Price)
	}
	if in.Condition != "" {
		add("condition", in.Condition)
	}
	if in.Photos != nil {
		add("photos", in.Photos)
	}
	if in.LengthCM != nil {
		add("length_cm", in.LengthCM)
	}
	if in.WidthCM != nil {
		add("width_cm", in.WidthCM)
	}
	if in.HeightCM != nil {
		add("height_cm", in.HeightCM)
	}
	if in.WeightGram != nil {
		add("weight_grams", in.WeightGram)
	}

	// WARNING: This logic prevents setting IsSold to false (making item available again).
	// To fix, you must change Product.IsSold to *bool.
	if in.IsSold {
		add("is_sold", in.IsSold)
	}

	if len(set) == 0 {
		json.NewEncoder(w).Encode(map[string]string{"status": "no changes"})
		return
	}

	query := fmt.Sprintf(
		"UPDATE products SET %s, updated_at = now() WHERE id = $%d AND deleted_at IS NULL",
		strings.Join(set, ", "),
		arg,
	)
	args = append(args, id)

	_, err = db.Exec(r.Context(), query, args...)
	if err != nil {
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}

// DELETE /products/{id}
func productDeleteHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(userIDKey).(int)

	// FIX: Parse ID correctly
	idStr := r.PathValue("id")
	var productID int64
	fmt.Sscanf(idStr, "%d", &productID)

	var owner int
	err := db.QueryRow(r.Context(),
		"SELECT user_id FROM products WHERE id=$1 AND deleted_at IS NULL",
		productID,
	).Scan(&owner)

	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if owner != userID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	_, err = db.Exec(r.Context(),
		"UPDATE products SET deleted_at = now(), updated_at = now() WHERE id=$1 AND deleted_at IS NULL",
		productID,
	)

	if err != nil {
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}

	w.Write([]byte(`{"status":"soft_deleted"}`))
}

// DELETE /products/{id}/hard
func productHardDeleteHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(userIDKey).(int)

	// FIX: Parse ID correctly
	idStr := r.PathValue("id")
	var productID int64
	fmt.Sscanf(idStr, "%d", &productID)

	var owner int
	err := db.QueryRow(r.Context(), "SELECT user_id FROM products WHERE id=$1", productID).Scan(&owner)

	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if owner != userID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	_, err = db.Exec(r.Context(), "DELETE FROM products WHERE id=$1", productID)

	if err != nil {
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}

	w.Write([]byte(`{"status":"hard_deleted"}`))
}

//// CART HANDLERS ////

func cartAddHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(userIDKey).(int)

	var in struct {
		ProductID int `json:"product_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad input", http.StatusBadRequest)
		return
	}

	// Check if product exists, is not sold, and NOT owned by user
	var ownerID int
	var isSold bool
	err := db.QueryRow(r.Context(), "SELECT user_id, is_sold FROM products WHERE id=$1 AND deleted_at IS NULL", in.ProductID).Scan(&ownerID, &isSold)
	if err != nil {
		http.Error(w, "product not found", http.StatusNotFound)
		return
	}

	if ownerID == userID {
		http.Error(w, "cannot buy your own product", http.StatusBadRequest)
		return
	}
	if isSold {
		http.Error(w, "product is already sold", http.StatusBadRequest)
		return
	}

	// Insert into cart (ignore duplicates via ON CONFLICT if needed, or let it error)
	_, err = db.Exec(r.Context(),
		`INSERT INTO cart_items (user_id, product_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		userID, in.ProductID,
	)
	if err != nil {
		http.Error(w, "failed to add to cart", http.StatusInternalServerError)
		return
	}

	w.Write([]byte(`{"status":"added"}`))
}

func cartRemoveHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(userIDKey).(int)
	idStr := r.PathValue("productID")

	var productID int
	fmt.Sscanf(idStr, "%d", &productID)

	_, err := db.Exec(r.Context(), "DELETE FROM cart_items WHERE user_id=$1 AND product_id=$2", userID, productID)
	if err != nil {
		http.Error(w, "failed to remove", http.StatusInternalServerError)
		return
	}

	w.Write([]byte(`{"status":"removed"}`))
}

func cartListHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(userIDKey).(int)

	// Join products and users (to get seller name)
	rows, err := db.Query(r.Context(), `
        SELECT p.id, p.user_id, u.full_name, p.title, p.price, p.photos, p.is_sold
        FROM cart_items c
        JOIN products p ON c.product_id = p.id
        JOIN users u ON p.user_id = u.id
        WHERE c.user_id = $1 AND p.deleted_at IS NULL
        ORDER BY p.user_id, p.created_at DESC
    `, userID)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Grouping logic
	// Map sellerID -> CartGroup
	grouped := make(map[int]*CartGroup)
	// To keep order consistent (optional), we could use a slice of IDs,
	// but for simplicity we rely on the map for now.

	for rows.Next() {
		var p Product
		var sellerID int
		var sellerName *string // nullable in DB, but usually set

		// We scan minimal fields for the cart view
		err := rows.Scan(&p.ID, &sellerID, &sellerName, &p.Title, &p.Price, &p.Photos, &p.IsSold)
		if err != nil {
			continue
		}

		p.UserID = sellerID // Ensure struct has it

		sName := "Unknown"
		if sellerName != nil {
			sName = *sellerName
		}

		if _, exists := grouped[sellerID]; !exists {
			grouped[sellerID] = &CartGroup{
				SellerID:   sellerID,
				SellerName: sName,
				Items:      []Product{},
			}
		}
		grouped[sellerID].Items = append(grouped[sellerID].Items, p)
	}

	// Convert map to slice
	res := []CartGroup{}
	for _, g := range grouped {
		res = append(res, *g)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

//// CHECKOUT & ORDER HANDLERS ////

func checkoutHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(userIDKey).(int)

	var in struct {
		SellerID int `json:"seller_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad input", http.StatusBadRequest)
		return
	}

	// 1. Get Buyer Address (Snapshot)
	var address *string
	err := db.QueryRow(r.Context(), "SELECT address FROM users WHERE id=$1", userID).Scan(&address)
	if err != nil || address == nil || *address == "" {
		http.Error(w, "please set your shipping address in profile", http.StatusBadRequest)
		return
	}

	// 2. Start Transaction
	tx, err := db.Begin(r.Context())
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(r.Context())

	// 3. Lock & Fetch Cart Items for this Seller
	// We use FOR UPDATE on the products table to prevent race conditions
	rows, err := tx.Query(r.Context(), `
        SELECT p.id, p.price 
        FROM cart_items c
        JOIN products p ON c.product_id = p.id
        WHERE c.user_id = $1 AND p.user_id = $2 AND p.is_sold = false AND p.deleted_at IS NULL
        FOR UPDATE OF p
    `, userID, in.SellerID)
	if err != nil {
		http.Error(w, "failed to fetch items", http.StatusInternalServerError)
		return
	}

	type itemToBuy struct {
		ID    int64
		Price int
	}
	items := []itemToBuy{}
	totalPrice := 0

	for rows.Next() {
		var it itemToBuy
		if err := rows.Scan(&it.ID, &it.Price); err != nil {
			continue
		}
		items = append(items, it)
		totalPrice += it.Price
	}
	rows.Close()

	if len(items) == 0 {
		http.Error(w, "no available items from this seller in cart", http.StatusBadRequest)
		return
	}

	// 4. Create Order
	// Hardcoded logic: AppFee is 1% or flat? Lets say flat 5000 for now or 0.
	shippingCost := 0 // Will be calculated later via API
	appFee := 0       // Calculate your cut here
	grandTotal := totalPrice + shippingCost + appFee

	var orderID int
	err = tx.QueryRow(r.Context(), `
        INSERT INTO orders 
        (buyer_id, seller_id, status, total_price, shipping_cost, app_fee, grand_total, shipping_address)
        VALUES ($1, $2, 'PENDING_PAYMENT', $3, $4, $5, $6, $7)
        RETURNING id
    `, userID, in.SellerID, totalPrice, shippingCost, appFee, grandTotal, *address).Scan(&orderID)

	if err != nil {
		http.Error(w, "failed to create order", http.StatusInternalServerError)
		return
	}

	// 5. Process Items: Insert OrderItems + Mark Sold + Remove from Cart
	for _, it := range items {
		// A. Snapshot in order_items
		_, err = tx.Exec(r.Context(),
			"INSERT INTO order_items (order_id, product_id, price_at_purchase) VALUES ($1, $2, $3)",
			orderID, it.ID, it.Price)
		if err != nil {
			return
		}

		// B. Mark as Sold (Inventory Reservation)
		_, err = tx.Exec(r.Context(), "UPDATE products SET is_sold = true, updated_at = now() WHERE id = $1", it.ID)
		if err != nil {
			return
		}

		// C. Remove from Cart
		_, err = tx.Exec(r.Context(), "DELETE FROM cart_items WHERE user_id = $1 AND product_id = $2", userID, it.ID)
		if err != nil {
			return
		}
	}

	if err := tx.Commit(r.Context()); err != nil {
		http.Error(w, "transaction commit failed", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "created",
		"order_id":    orderID,
		"grand_total": grandTotal,
	})
}

func orderCancelHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(userIDKey).(int)
	idStr := r.PathValue("id")
	var orderID int
	fmt.Sscanf(idStr, "%d", &orderID)

	tx, err := db.Begin(r.Context())
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(r.Context())

	// 1. Verify Ownership & Status
	var status string
	err = tx.QueryRow(r.Context(), "SELECT status FROM orders WHERE id=$1 AND buyer_id=$2 FOR UPDATE", orderID, userID).Scan(&status)
	if err != nil {
		http.Error(w, "order not found or forbidden", http.StatusNotFound)
		return
	}

	if status != "PENDING_PAYMENT" {
		http.Error(w, "cannot cancel order in this state", http.StatusBadRequest)
		return
	}

	// 2. Update Order Status
	_, err = tx.Exec(r.Context(), "UPDATE orders SET status='CANCELLED', updated_at=now() WHERE id=$1", orderID)
	if err != nil {
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}

	// 3. Release Inventory (Set is_sold = false)
	// We join order_items to find which products to release
	_, err = tx.Exec(r.Context(), `
        UPDATE products 
        SET is_sold = false, updated_at = now()
        FROM order_items
        WHERE products.id = order_items.product_id AND order_items.order_id = $1
    `, orderID)
	if err != nil {
		http.Error(w, "failed to release inventory", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		http.Error(w, "commit failed", http.StatusInternalServerError)
		return
	}

	w.Write([]byte(`{"status":"cancelled"}`))
}

//// MEDIA UPLOAD HANDLER ////

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	// Limit upload size (e.g., 10MB) to prevent RAM DoS
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "file too big", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("image") // Frontend must use key "image"
	if err != nil {
		http.Error(w, "invalid file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	url, err := processAndUpload(file, header)
	if err != nil {
		log.Printf("Upload Error: %v", err)
		http.Error(w, "upload failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"url": url})

	log.Printf("Content-Type: %s", r.Header.Get("Content-Type"))
	log.Printf("Content-Length: %s", r.Header.Get("Content-Length"))
}

func searchLocationHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Get query param
	query := r.URL.Query().Get("q")
	if len(query) < 3 {
		http.Error(w, "query too short", http.StatusBadRequest)
		return
	}

	// 2. Prepare Request to Komship
	// Endpoint: https://rajaongkir.komerce.id/api/v1/destination/domestic-destination?search=...
	targetURL := fmt.Sprintf("https://rajaongkir.komerce.id/api/v1/destination/domestic-destination?search=%s", query)

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// 3. Set Headers (Crucial for Komship)
	// Check if key is present
	if komshipAPIKey == "" {
		// Fallback or Error if key is missing in Env
		log.Println("ERROR: KOMSHIP_API_KEY is not set")
		http.Error(w, "service configuration error", http.StatusInternalServerError)
		return
	}
	req.Header.Set("key", komshipAPIKey)
	req.Header.Set("Accept", "application/json")

	// 4. Execute
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "upstream api failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 5. Proxy the Response back to frontend
	// We copy the status code and the body directly
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)

	// Efficiently stream the body without loading it all into memory
	// (You can use io.Copy here since it's stdlib and simple)
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Println("error copying response:", err)
	}
}

//// SHIPPING HANDLER ////

func calculateShippingHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(userIDKey).(int)

	// 1. Parse Input
	var in struct {
		SellerID int    `json:"seller_id"`
		Courier  string `json:"courier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad input", http.StatusBadRequest)
		return
	}

	// 2. Whitelist Check
	// Supported couriers by Komerce/RajaOngkir
	allowedCouriers := map[string]bool{
		"jne": true, "sicepat": true, "ninja": true, "jnt": true,
		"tiki": true, "wahana": true, "pos": true, "lion": true,
	}
	if !allowedCouriers[in.Courier] {
		http.Error(w, "unsupported courier", http.StatusBadRequest)
		return
	}

	// 3. Database "Triangulation" (Buyer Loc, Seller Loc, Weight)
	var buyerLoc, sellerLoc *int
	var totalWeight int

	// A. Get Buyer Location
	err := db.QueryRow(r.Context(), "SELECT location_id FROM users WHERE id = $1", userID).Scan(&buyerLoc)
	if err != nil {
		http.Error(w, "user not found", http.StatusInternalServerError)
		return
	}
	if buyerLoc == nil {
		http.Error(w, "please update your profile with a shipping address", http.StatusBadRequest)
		return
	}

	// B. Get Seller Location
	err = db.QueryRow(r.Context(), "SELECT location_id FROM users WHERE id = $1", in.SellerID).Scan(&sellerLoc)
	if err != nil {
		http.Error(w, "seller not found", http.StatusNotFound)
		return
	}
	if sellerLoc == nil {
		http.Error(w, "seller has not set a shipping location", http.StatusBadRequest)
		return
	}

	// C. Calculate Weight
	// Sum weight_grams of all products in cart for this seller
	// COALESCE(..., 1000) ensures we default to 1kg if cart is empty or weights are missing
	err = db.QueryRow(r.Context(), `
		SELECT COALESCE(SUM(p.weight_grams), 1000) 
		FROM cart_items c
		JOIN products p ON c.product_id = p.id
		WHERE c.user_id = $1 AND p.user_id = $2
	`, userID, in.SellerID).Scan(&totalWeight)

	if err != nil {
		// If query fails, fallback to 1kg so the API call doesn't break
		log.Printf("Weight Calc Error: %v", err)
		totalWeight = 1000
	}
	// Sanity check: ensure at least 1 gram
	if totalWeight < 1 {
		totalWeight = 1000
	}

	// 4. Call Komerce API
	if komshipAPIKey == "" {
		log.Println("ERROR: KOMSHIP_API_KEY is not set")
		http.Error(w, "service configuration error", http.StatusInternalServerError)
		return
	}

	// Build Form Data (application/x-www-form-urlencoded)
	data := url.Values{}
	data.Set("origin", fmt.Sprintf("%d", *sellerLoc))
	data.Set("destination", fmt.Sprintf("%d", *buyerLoc))
	data.Set("weight", fmt.Sprintf("%d", totalWeight))
	data.Set("courier", in.Courier)

	targetURL := "https://rajaongkir.komerce.id/api/v1/calculate/domestic-cost"
	req, err := http.NewRequest("POST", targetURL, strings.NewReader(data.Encode()))
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// Set Headers (Raw 'key' header, no Bearer)
	req.Header.Set("key", komshipAPIKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("ERROR: Shipping API request failed: %v", err)
		http.Error(w, "upstream api failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 5. Proxy Response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)

	// Stream the JSON back to frontend
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Println("error copying response:", err)
	}
}

//// SEARCH HANDLER ////

func searchHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Parse Query
	rawQuery := r.URL.Query().Get("q")
	if len(rawQuery) < 2 { // Don't search for single letters
		http.Error(w, "query too short", http.StatusBadRequest)
		return
	}

	// Prepare the search term for ILIKE (e.g., "%ibanez%")
	searchTerm := fmt.Sprintf("%%%s%%", rawQuery)

	resp := SearchResponse{
		Users:    []UserPreview{},
		Products: []ProductPreview{},
	}

	// 2. SEARCH USERS (Shops)
	// We use ILIKE which now uses the GIN Index we created!
	userQuery := `
		SELECT id, COALESCE(full_name, email), profile_picture, city 
		FROM users 
		WHERE full_name ILIKE $1 
		LIMIT 5
	`
	uRows, err := db.Query(r.Context(), userQuery, searchTerm)
	if err != nil {
		log.Printf("Search Users Error: %v", err)
		http.Error(w, "search failed", http.StatusInternalServerError)
		return
	}
	defer uRows.Close()

	for uRows.Next() {
		var u UserPreview
		// Note: We use COALESCE in SQL, so FullName won't be null
		if err := uRows.Scan(&u.ID, &u.FullName, &u.ProfilePicture, &u.Location); err != nil {
			continue
		}
		resp.Users = append(resp.Users, u)
	}

	// 3. SEARCH PRODUCTS (Gear)
	// We search Title OR Description using the GIN indexes
	prodQuery := `
		SELECT p.id, p.title, p.price, p.condition, p.photos[1], COALESCE(u.full_name, 'Unknown')
		FROM products p
		JOIN users u ON p.user_id = u.id
		WHERE (p.title ILIKE $1 OR p.description ILIKE $1 OR p.brand ILIKE $1)
		AND p.is_sold = false 
		AND p.deleted_at IS NULL
		LIMIT 20
	`
	pRows, err := db.Query(r.Context(), prodQuery, searchTerm)
	if err != nil {
		log.Printf("Search Products Error: %v", err)
		http.Error(w, "search failed", http.StatusInternalServerError)
		return
	}
	defer pRows.Close()

	for pRows.Next() {
		var p ProductPreview
		if err := pRows.Scan(&p.ID, &p.Title, &p.Price, &p.Condition, &p.Thumbnail, &p.SellerName); err != nil {
			continue
		}
		resp.Products = append(resp.Products, p)
	}

	// 4. Return JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// // MY ORDERS HANDLER ////
func listBuyingHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(userIDKey).(int)

	// Query: Find orders where I am the BUYER. Join USERS to get Seller Name.
	query := `
		SELECT o.id, o.status, o.grand_total, o.created_at, u.full_name
		FROM orders o
		JOIN users u ON o.seller_id = u.id
		WHERE o.buyer_id = $1
		ORDER BY o.created_at DESC
		LIMIT 50
	`
	rows, err := db.Query(r.Context(), query, userID)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var orders []OrderPreview
	for rows.Next() {
		var o OrderPreview
		if err := rows.Scan(&o.ID, &o.Status, &o.GrandTotal, &o.CreatedAt, &o.Counterparty); err != nil {
			continue
		}

		// Micro-Optimization: Get the first item's details for the "Preview Card"
		// We do this inside the loop (N+1 query) which is acceptable for <50 items in Postgres.
		_ = db.QueryRow(r.Context(), `
			SELECT p.title, p.photos[1], (SELECT COUNT(*) FROM order_items WHERE order_id = $1)
			FROM order_items oi
			JOIN products p ON oi.product_id = p.id
			WHERE oi.order_id = $1
			LIMIT 1
		`, o.ID).Scan(&o.FirstItemTitle, &o.FirstItemPhoto, &o.TotalItems)

		orders = append(orders, o)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(orders)
}

func listSellingHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(userIDKey).(int)

	// Query: Find orders where I am the SELLER. Join USERS to get Buyer Name.
	query := `
		SELECT o.id, o.status, o.grand_total, o.created_at, u.full_name
		FROM orders o
		JOIN users u ON o.buyer_id = u.id
		WHERE o.seller_id = $1
		ORDER BY o.created_at DESC
		LIMIT 50
	`
	rows, err := db.Query(r.Context(), query, userID)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var orders []OrderPreview
	for rows.Next() {
		var o OrderPreview
		if err := rows.Scan(&o.ID, &o.Status, &o.GrandTotal, &o.CreatedAt, &o.Counterparty); err != nil {
			continue
		}

		// Get First Item Preview
		_ = db.QueryRow(r.Context(), `
			SELECT p.title, p.photos[1], (SELECT COUNT(*) FROM order_items WHERE order_id = $1)
			FROM order_items oi
			JOIN products p ON oi.product_id = p.id
			WHERE oi.order_id = $1
			LIMIT 1
		`, o.ID).Scan(&o.FirstItemTitle, &o.FirstItemPhoto, &o.TotalItems)

		orders = append(orders, o)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(orders)
}

func orderDetailHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(userIDKey).(int)

	// Extract Order ID from URL (naive string trimming or regex)
	// Assuming path is /orders/{id}
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 3 {
		http.Error(w, "invalid order id", http.StatusBadRequest)
		return
	}
	orderID := pathParts[len(pathParts)-1]

	var o OrderDetail
	var buyerID, sellerID int

	// 1. Fetch Order Header & Verify Ownership
	// We join twice to get BOTH names
	query := `
		SELECT o.id, o.status, o.grand_total, o.shipping_cost, o.shipping_address, o.tracking_number, o.created_at,
		       o.buyer_id, o.seller_id,
		       b.full_name, s.full_name
		FROM orders o
		JOIN users b ON o.buyer_id = b.id
		JOIN users s ON o.seller_id = s.id
		WHERE o.id = $1
	`
	err := db.QueryRow(r.Context(), query, orderID).Scan(
		&o.ID, &o.Status, &o.GrandTotal, &o.ShippingCost, &o.ShippingAddress, &o.TrackingNumber, &o.CreatedAt,
		&buyerID, &sellerID,
		&o.BuyerName, &o.SellerName,
	)

	if err != nil {
		http.Error(w, "order not found", http.StatusNotFound)
		return
	}

	// SECURITY: Am I the buyer or the seller?
	if userID != buyerID && userID != sellerID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// 2. Fetch Order Items
	itemQuery := `
		SELECT p.id, p.title, p.photos[1], oi.price_at_purchase
		FROM order_items oi
		JOIN products p ON oi.product_id = p.id
		WHERE oi.order_id = $1
	`
	rows, err := db.Query(r.Context(), itemQuery, o.ID)
	if err != nil {
		// Log error but return what we have
		log.Printf("Error fetching items: %v", err)
	} else {
		defer rows.Close()
		for rows.Next() {
			var i OrderItem
			if err := rows.Scan(&i.ProductID, &i.Title, &i.Photo, &i.Price); err == nil {
				o.Items = append(o.Items, i)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(o)
}

// // STOREFRONT SHOP HANDLER ////
func shopHandler(w http.ResponseWriter, r *http.Request) {
	// Extract username from URL path
	// Assuming route is /shops/{username}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 3 {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	username := strings.ToLower(parts[len(parts)-1])

	ctx := r.Context()
	var shop ShopProfile

	// 1. Fetch User ProfileM
	// We only show safe public info
	userQuery := `
		SELECT id, username, COALESCE(full_name, 'New User'), profile_picture, city, created_at
		FROM users 
		WHERE username = $1
	`
	err := db.QueryRow(ctx, userQuery, username).Scan(
		&shop.ID, &shop.Username, &shop.FullName, &shop.ProfilePicture, &shop.Location, &shop.JoinedAt,
	)
	if err != nil {
		http.Error(w, "shop not found", http.StatusNotFound)
		return
	}

	// 2. Fetch Active Inventory (Reusing the logic from Search/Products)
	// Only show unsold, non-deleted items
	prodQuery := `
		SELECT id, title, price, condition, photos[1]
		FROM products 
		WHERE user_id = $1 AND is_sold = false AND deleted_at IS NULL
		ORDER BY created_at DESC
	`
	rows, err := db.Query(ctx, prodQuery, shop.ID)
	if err != nil {
		// Log error but return the profile (empty inventory is fine)
		log.Printf("Shop Inventory Error: %v", err)
	} else {
		defer rows.Close()
		for rows.Next() {
			var p ProductPreview
			// Note: We don't need SellerName here since we know who owns the shop
			if err := rows.Scan(&p.ID, &p.Title, &p.Price, &p.Condition, &p.Thumbnail); err == nil {
				shop.Inventory = append(shop.Inventory, p)
			}
		}
	}

	if shop.Inventory == nil {
		shop.Inventory = []ProductPreview{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(shop)
}
