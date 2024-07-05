package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	regexp "regexp"
	"strings"
	time "time"
	"os"

	"github.com/golang-jwt/jwt/v5"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
    "github.com/joho/godotenv"
)

type User struct {
	UserID    int       `json:"user_id"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	Email     string    `json:"email"`
	Country   string    `json:"country"`
	CreatedAt time.Time `json:"created_at"`
}

type Score struct {
	UserId     int     `json:"user_id"`
	Raw        int     `json:"raw"`
	Cpm        int     `json:"cpm"`
	Wpm        int     `json:"wpm"`
	Accuracy   float32 `json:"accuracy"`
	Duration   int     `json:"duration"`
	Difficulty string  `json:"difficulty"`
}

type App struct {
	DB *sql.DB
}

var secretKey []byte

func main() {
	fmt.Println("Starting server...")
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	dsn := os.Getenv("DSN")
	secretKeyString := os.Getenv("SECRET_KEY")

	secretKey = []byte(secretKeyString)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	} else {
		fmt.Println("Database connected")
	}

	app := &App{DB: db}

	http.HandleFunc("POST /register", app.handleRegister)
	http.HandleFunc("POST /login", app.handleLogin)
	http.HandleFunc("GET /leaderboard", AuthMiddleware(app.handleLeaderboard))
	http.HandleFunc("POST /scores", AuthMiddleware(app.handleScore))
	http.HandleFunc("GET /profile", AuthMiddleware(app.handleProfile))

	log.Fatal(http.ListenAndServe(":8080", nil)) 
}

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")

		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if !strings.Contains(tokenString, "Bearer ") {
			http.Error(w, "Invalid token", http.StatusBadRequest)
			return
		}

		tokenString = strings.Replace(tokenString, "Bearer ", "", -1)

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return secretKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (a *App) handleScore(w http.ResponseWriter, r *http.Request) {
	var score Score

	if err := json.NewDecoder(r.Body).Decode(&score); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Println(err)
		return
	}
	defer r.Body.Close() 

	if score.UserId == 0 || score.Raw == 0 || score.Cpm == 0 || score.Wpm == 0 || score.Accuracy == 0 || score.Duration == 0 || score.Difficulty == "" {
		http.Error(w, "All fields are required", http.StatusBadRequest)
		return
	}

	_, err := a.DB.Exec("INSERT INTO scores (user_id, raw, cpm, wpm, accuracy, duration, difficulty, text_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		score.UserId, score.Raw, score.Cpm, score.Wpm, score.Accuracy, score.Duration, score.Difficulty, 1)
	if err != nil {
		http.Error(w, "Error saving score", http.StatusInternalServerError)
		log.Println(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Score saved"})
}

func (a *App) handleRegister(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.Host)
	var user User

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close() 

	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if user.Username == "" || user.Password == "" || user.Email == "" {
		http.Error(w, "All fields are required", http.StatusBadRequest)
		return
	} else if len(user.Password) < 6 {
		http.Error(w, "Password must be at least 6 characters", http.StatusBadRequest)
		return
	} else if !emailRegex.MatchString(user.Email) {
		http.Error(w, "Invalid email address", http.StatusBadRequest)
		return
	}

	hashedPassword, _ := HashPassword(user.Password) 

	_, err := a.DB.Exec("INSERT INTO users (username, password, email, country) VALUES (?, ?, ?, ?)",
		user.Username, hashedPassword, user.Email, user.Country)
	if err != nil {
		http.Error(w, "Error registering user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "User created"})
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var user User

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close() 

	if user.Username == "" || user.Password == "" {
		http.Error(w, "All fields are required", http.StatusBadRequest)
		return
	}

	var storedPassword string
	err := a.DB.QueryRow("SELECT user_id, created_at, password FROM users WHERE username = ?", user.Username).Scan(&user.UserID, &user.CreatedAt, &storedPassword)
	if err != nil {
		log.Println("Error fetching user", err)
		http.Error(w, "We couldn't find the username", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(user.Password))
	if err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	tokenString, err := createToken(user.Username) 
	if err != nil {
		log.Println("Error generating token", err)
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "User logged in", "token": tokenString, "user_id": fmt.Sprintf("%d", user.UserID), "created_at": user.CreatedAt.String(), "username": user.Username})
}

func (a *App) handleLeaderboard(w http.ResponseWriter, r *http.Request) {
	rows, err := a.DB.Query(`SELECT
    users.username,
    MAX(scores.wpm) AS top_wpm,
    MAX(scores.created_at) AS top_wpm_date
FROM scores
INNER JOIN users ON scores.user_id = users.user_id
GROUP BY users.username
ORDER BY top_wpm DESC LIMIT 10;`)
	if err != nil {
		http.Error(w, "Error fetching leaderboard", http.StatusInternalServerError)
		log.Println(err)
		return
	}
	defer rows.Close()

	var leaderboard []map[string]interface{}
	for rows.Next() {
		var username string
		var wpm int
		var created_at time.Time

		err := rows.Scan(&username, &wpm, &created_at)
		if err != nil {
			http.Error(w, "Error fetching leaderboard", http.StatusInternalServerError)
			log.Println(err)
			return
		}

		leaderboard = append(leaderboard, map[string]interface{}{
			"username": username,
			"wpm":      wpm,
			"created_at": created_at,
		})

	}

	leaderboardData := map[string]interface{}{
		"status": "success",
		"leaderboard": leaderboard,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(leaderboardData)
}

func (a *App) handleProfile(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	tokenString = strings.Replace(tokenString, "Bearer ", "", -1)
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	claims, _ := token.Claims.(jwt.MapClaims)
	username := claims["sub"].(string)

	var userID int
	err := a.DB.QueryRow("SELECT user_id FROM users WHERE username = ?", username).Scan(&userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		log.Println("Error fetching user ID:", err)
		return
	}

	var totalTests int
	var avgWPM float64
	var topWPM int
	var avgAccuracy float64

	err = a.DB.QueryRow(`
        SELECT COUNT(*), AVG(wpm), MAX(wpm), AVG(accuracy)
        FROM scores
        WHERE user_id = ?
    `, userID).Scan(&totalTests, &avgWPM, &topWPM, &avgAccuracy)
	if err != nil {
		http.Error(w, "Error fetching profile statistics", http.StatusInternalServerError)
		log.Println("Error fetching profile statistics:", err)
		return
	}

	rows, err := a.DB.Query(`
        SELECT wpm, accuracy, created_at
        FROM scores
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 10
    `, userID)
	if err != nil {
		http.Error(w, "Error fetching last 10 scores", http.StatusInternalServerError)
		log.Println("Error fetching last 10 scores:", err)
		return
	}
	defer rows.Close()

	var last10Scores []map[string]interface{}

	for rows.Next() {
		var wpm int
		var createdAt time.Time
		var accuracy float32
		if err := rows.Scan(&wpm, &accuracy, &createdAt); err != nil {
			http.Error(w, "Error scanning last 10 scores", http.StatusInternalServerError)
			log.Println("Error scanning last 10 scores:", err)
			return
		}
		score := map[string]interface{}{
			"wpm":        wpm,
			"accuracy":   accuracy,
			"created_at": createdAt.Format(time.RFC3339), 
		}
		last10Scores = append(last10Scores, score)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "Error iterating over last 10 scores", http.StatusInternalServerError)
		log.Println("Error iterating over last 10 scores:", err)
		return
	}

	profileData := map[string]interface{}{
		"total_tests":    totalTests,
		"avg_wpm":        int(avgWPM),
		"top_wpm":        topWPM,
		"avg_accuracy":   fmt.Sprintf("%.2f%%", avgAccuracy),
		"last_10_scores": last10Scores,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(profileData)
}

func createToken(username string) (string, error) { 
	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(48 * time.Hour)),
		Issuer:    "kibby",
		Subject:   username,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}