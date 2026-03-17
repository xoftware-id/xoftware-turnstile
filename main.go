package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/rs/cors"
)

var (
	HMAC_SECRET_KEY      string
	ISSUER_NAME          string
	TOKEN_EXPIRATION     time.Duration
	CHALLENGE_EXPIRATION time.Duration
	POW_DIFFICULTY       int
	SERVER_PORT          string
)

var (
	usedChallenges = make(map[string]bool)
	mu             sync.RWMutex
)

type ChallengeResponse struct {
	Challenge  string `json:"challenge"`
	Difficulty int    `json:"difficulty"`
	Signature  string `json:"signature"`
	ExpiresAt  int64  `json:"expires_at"`
	Obfuscator string `json:"obfuscator"`
}

type SolutionRequest struct {
	Challenge       string `json:"challenge"`
	Nonce           string `json:"nonce"`
	Origin          string `json:"origin"`
	Fingerprint     string `json:"fingerprint"`
	Signature       string `json:"signature"`
	ExpiresAt       int64  `json:"expires_at"`
	CanvasData      string `json:"canvas_data"`
	Obfuscator      string `json:"obfuscator,omitempty"`
	UserInteracted  bool   `json:"user_interacted"`
	SecurityPayload string `json:"security_payload"`
}

type ApiResponse struct {
	Success bool   `json:"success"`
	Token   string `json:"token,omitempty"`
	Error   string `json:"error,omitempty"`
}

func init() {
	if err := godotenv.Load(); err != nil {
		log.Println("Peringatan: File .env tidak ditemukan, menggunakan system env")
	}
	HMAC_SECRET_KEY = getEnv("HMAC_SECRET_KEY", "super_default_secret_change_me")
	ISSUER_NAME = getEnv("ISSUER_NAME", "fortress-turnstile")
	SERVER_PORT = getEnv("SERVER_PORT", ":8071")
	POW_DIFFICULTY = getEnvInt("POW_DIFFICULTY", 5)
	var err error
	TOKEN_EXPIRATION, err = time.ParseDuration(getEnv("TOKEN_EXPIRATION", "5m"))
	if err != nil {
		TOKEN_EXPIRATION = 5 * time.Minute
	}

	CHALLENGE_EXPIRATION, err = time.ParseDuration(getEnv("CHALLENGE_EXPIRATION", "2m"))
	if err != nil {
		CHALLENGE_EXPIRATION = 2 * time.Minute
	}
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/turnstile/challenge", handleGetChallenge)
	mux.HandleFunc("/api/turnstile/verify", handleVerifySolution)
	mux.HandleFunc("/api/auth/login", handleLogin)
	fs := http.FileServer(http.Dir("./static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "X-Requested-With", "X-Security-Check"},
		AllowCredentials: false,
	})

	fmt.Printf("🚀 Fortress Turnstile running on %s\n", SERVER_PORT)
	log.Fatal(http.ListenAndServe(SERVER_PORT, c.Handler(mux)))
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}

func generateObfuscator() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func isSuspiciousRequest(r *http.Request) bool {
	ua := strings.ToLower(r.UserAgent())
	badKeywords := []string{"headless", "puppeteer", "selenium", "phantomjs", "webdriver", "bot", "crawl", "spider", "curl", "python", "java", "okhttp"}
	for _, kw := range badKeywords {
		if strings.Contains(ua, kw) {
			return true
		}
	}
	if r.Header.Get("Accept-Language") == "" {
		return true
	}
	return false
}

func handleGetChallenge(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 32)
	rand.Read(b)
	challenge := hex.EncodeToString(b)
	exp := time.Now().Add(CHALLENGE_EXPIRATION).Unix()
	obf := generateObfuscator()
	mac := hmac.New(sha256.New, []byte(HMAC_SECRET_KEY))
	mac.Write([]byte(fmt.Sprintf("%s:%d:%s", challenge, exp, obf)))
	signature := hex.EncodeToString(mac.Sum(nil))

	resp := ChallengeResponse{
		Challenge:  challenge,
		Difficulty: POW_DIFFICULTY,
		ExpiresAt:  exp,
		Signature:  signature,
		Obfuscator: obf,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleVerifySolution(w http.ResponseWriter, r *http.Request) {
	var req SolutionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	mac := hmac.New(sha256.New, []byte(HMAC_SECRET_KEY))
	mac.Write([]byte(fmt.Sprintf("%s:%d:%s", req.Challenge, req.ExpiresAt, req.Obfuscator)))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	isValidSig := hmac.Equal([]byte(req.Signature), []byte(expectedSig))
	if !isValidSig && req.Obfuscator == "" {
		macSimple := hmac.New(sha256.New, []byte(HMAC_SECRET_KEY))
		macSimple.Write([]byte(fmt.Sprintf("%s:%d", req.Challenge, req.ExpiresAt)))
		expectedSigSimple := hex.EncodeToString(macSimple.Sum(nil))
		isValidSig = hmac.Equal([]byte(req.Signature), []byte(expectedSigSimple))
	}

	if !isValidSig {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ApiResponse{Success: false, Error: "Invalid signature"})
		return
	}

	if time.Now().Unix() > req.ExpiresAt {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ApiResponse{Success: false, Error: "Challenge expired"})
		return
	}

	mu.Lock()
	if usedChallenges[req.Challenge] {
		mu.Unlock()
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ApiResponse{Success: false, Error: "Challenge already used"})
		return
	}
	usedChallenges[req.Challenge] = true
	mu.Unlock()

	isServerSuspicious := isSuspiciousRequest(r)
	if isServerSuspicious {
		if !req.UserInteracted {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(ApiResponse{Success: false, Error: "Verification requires human interaction"})
			return
		}
		log.Printf("WARNING: Request passed with suspicious UA but provided interaction: %s", r.UserAgent())
	}

	if len(req.CanvasData) < 10 {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ApiResponse{Success: false, Error: "Browser check failed"})
		return
	}

	if req.SecurityPayload == "devtools_detected" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ApiResponse{Success: false, Error: "Environment insecure (DevTools detected)"})
		return
	}

	data := fmt.Sprintf("%s%s%s%s%s", req.Challenge, req.Nonce, req.Origin, req.Fingerprint, req.CanvasData[:10])
	hash := sha256.Sum256([]byte(data))
	hashHex := hex.EncodeToString(hash[:])
	targetPrefix := strings.Repeat("0", POW_DIFFICULTY)

	if !strings.HasPrefix(hashHex, targetPrefix) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ApiResponse{Success: false, Error: "Invalid Proof of Work"})
		return
	}

	claims := jwt.MapClaims{
		"iss":  ISSUER_NAME,
		"orig": req.Origin,
		"fp":   req.Fingerprint,
		"exp":  time.Now().Add(TOKEN_EXPIRATION).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(HMAC_SECRET_KEY))
	if err != nil {
		http.Error(w, "Token generation failed", http.StatusInternalServerError)
		return
	}

	resp := ApiResponse{
		Success: true,
		Token:   signedToken,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ApiResponse{Error: "Token missing"})
		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(HMAC_SECRET_KEY), nil
	})

	if err != nil || !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ApiResponse{Error: "Invalid Token"})
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	requestOrigin := r.Header.Get("Origin")
	if claims["orig"] != requestOrigin {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ApiResponse{Error: "Origin mismatch"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Login allowed by fortress",
	})
}
