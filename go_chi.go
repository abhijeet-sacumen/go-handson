package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB
var secretKey = []byte("sfgvsdfgksj") // Change this to a strong secret key in production

// User struct represents a user
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Post struct represents a post
type Post struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
	Body  string `json:"body"`
}

func main() {
	// Open SQLite database
	var err error
	db, err = sql.Open("sqlite3", "./database.db")
	if err != nil {
		fmt.Println("Error opening database:", err)
		os.Exit(1)
	}
	defer db.Close()

	// Create tables if not exists
	createTables()

	// Populate tables with sample data
	populateData()

	// Create Chi router
	r := chi.NewRouter()

	// Use Chi logging middleware
	r.Use(middleware.Logger)

	// Define endpoints
	r.Post("/login", loginHandler)
	r.Group(func(r chi.Router) {
		// Use JWT authentication middleware for all routes under /api
		r.Use(jwtAuthentication)

		r.Get("/api/users", getUsersHandler)
		r.Get("/api/posts", getPostsHandler)
		r.Post("/api/create_posts", createPostHandler)
		r.Delete("/api/delete_posts/{id}", deletePostHandler)
		r.Put("/api/update_posts/{id}", updatePostHandler)
	})

	// Start server
	http.ListenAndServe(":8080", r)
}

func createTables() {
	// Create users table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL,
			password TEXT NOT NULL
		)
	`)
	if err != nil {
		fmt.Println("Error creating users table:", err)
		os.Exit(1)
	}

	// Create posts table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS posts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			title TEXT NOT NULL,
			body TEXT NOT NULL
		)
	`)
	if err != nil {
		fmt.Println("Error creating posts table:", err)
		os.Exit(1)
	}
}

func populateData() {
	// Populate users table with sample data
	for i := 1; i <= 10; i++ {
		username := fmt.Sprintf("user%d", i)
		password := fmt.Sprintf("password%d", i)

		_, err := db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, password)
		if err != nil {
			log.Println("Error populating users table:", err)
		}
	}

	// Populate posts table with sample data
	for i := 1; i <= 10; i++ {
		title := fmt.Sprintf("Post %d", i)
		body := fmt.Sprintf("Body of post %d", i)

		_, err := db.Exec("INSERT INTO posts (title, body) VALUES (?, ?)", title, body)
		if err != nil {
			log.Println("Error populating posts table:", err)
		}
	}
}

func generateToken(username string) (string, error) {
	// Create a new token
	token := jwt.New(jwt.SigningMethodHS256)
	// Set claims
	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = username
	claims["exp"] = time.Now().Add(time.Hour * 1).Unix() // Token expires in 1 hour

	// Sign the token with the secret key
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func jwtAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		// Check if the token has the "Bearer " prefix
		const prefix = "Bearer "
		if len(tokenString) > len(prefix) && tokenString[:len(prefix)] == prefix {
			// Remove the "Bearer " prefix
			tokenString = tokenString[len(prefix):]
		}

		// Parse the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return secretKey, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Parse username and password from the request body
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if the provided credentials match any user in the database
	var storedPassword string
	err = db.QueryRow("SELECT password FROM users WHERE username=?", credentials.Username).Scan(&storedPassword)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Verify the password
	if storedPassword != credentials.Password {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Generate a JWT token
	token, err := generateToken(credentials.Username)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"token":       token,
		"valid_until": time.Now().Add(time.Hour * 1).Format("01-06-2001T03:04:05PM"),
	}

	// Return the token in the response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func getUsersHandler(w http.ResponseWriter, r *http.Request) {
	users := []User{}
	rows, err := db.Query("SELECT id, username FROM users")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		users = append(users, user)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func getPostsHandler(w http.ResponseWriter, r *http.Request) {
	posts := []Post{}
	rows, err := db.Query("SELECT id, title, body FROM posts")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var post Post
		err := rows.Scan(&post.ID, &post.Title, &post.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		posts = append(posts, post)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(posts)
}

func createPostHandler(w http.ResponseWriter, r *http.Request) {
	// Parse JSON request
	var post Post
	err := json.NewDecoder(r.Body).Decode(&post)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Insert post into database
	_, err = db.Exec("INSERT INTO posts (title, body) VALUES (?, ?)", post.Title, post.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func deletePostHandler(w http.ResponseWriter, r *http.Request) {
	// Get post ID from URL parameter
	postID := chi.URLParam(r, "id")

	// Delete post from database
	_, err := db.Exec("DELETE FROM posts WHERE id=?", postID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func updatePostHandler(w http.ResponseWriter, r *http.Request) {
	// Get post ID from URL parameter
	postID := chi.URLParam(r, "id")

	// Parse JSON request
	var post Post
	err := json.NewDecoder(r.Body).Decode(&post)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Update post in the database
	_, err = db.Exec("UPDATE posts SET title=?, body=? WHERE id=?", post.Title, post.Body, postID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
