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
	dynamicRoutes = &sync.Map{}
)

type SessionData struct {
	Stage     int
	SessionID string
	CreatedAt time.Time
	TempData  string
}

type ChallengeResponse struct {
	NextEndpoint string `json:"next_endpoint"`
	Challenge    string `json:"challenge,omitempty"`
	Difficulty   int    `json:"difficulty,omitempty"`
	Signature    string `json:"signature,omitempty"`
	ExpiresAt    int64  `json:"expires_at,omitempty"`
	Obfuscator   string `json:"obfuscator,omitempty"`
	CanvasSeed   string `json:"canvas_seed,omitempty"`
}

type InitRequest struct {
	Telemetry ClientTelemetry `json:"telemetry"`
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

type ClientTelemetry struct {
	UserAgent       string `json:"user_agent"`
	IsWebDriver     bool   `json:"is_webdriver"`
	ScreenWidth     int    `json:"screen_width"`
	ScreenHeight    int    `json:"screen_height"`
	WindowInWidth   int    `json:"window_in_width"`
	WindowInHeight  int    `json:"window_in_height"`
	WindowOutWidth  int    `json:"window_out_width"`
	WindowOutHeight int    `json:"window_out_height"`
	DeviceMemory    int    `json:"device_memory"`
	CPUCore         int    `json:"cpu_core"`
}

type ApiResponse struct {
	Success      bool   `json:"success"`
	Token        string `json:"token,omitempty"`
	Error        string `json:"error,omitempty"`
	NextEndpoint string `json:"next_endpoint,omitempty"`
}

func init() {
	if err := godotenv.Load(); err != nil {
		log.Println("Peringatan: File .env tidak ditemukan")
	}
	HMAC_SECRET_KEY = getEnv("HMAC_SECRET_KEY", "super_default_secret_change_me")
	ISSUER_NAME = getEnv("ISSUER_NAME", "fortress-turnstile")
	SERVER_PORT = getEnv("SERVER_PORT", ":8071")
	POW_DIFFICULTY = getEnvInt("POW_DIFFICULTY", 5)
	TOKEN_EXPIRATION, _ = time.ParseDuration(getEnv("TOKEN_EXPIRATION", "5m"))
	CHALLENGE_EXPIRATION, _ = time.ParseDuration(getEnv("CHALLENGE_EXPIRATION", "2m"))
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/bootstrap", handleBootstrap)
	mux.HandleFunc("/", handleDynamicRouter)

	fs := http.FileServer(http.Dir("./static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "X-Requested-With"},
		AllowCredentials: false,
	})

	fmt.Printf("🚀 Server running on %s\n", SERVER_PORT)
	log.Fatal(http.ListenAndServe(SERVER_PORT, c.Handler(mux)))
}

func generateRoutePath() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "/x_" + hex.EncodeToString(b)
}

func handleBootstrap(w http.ResponseWriter, r *http.Request) {
	firstRoute := generateRoutePath()
	sessionID := hex.EncodeToString(make([]byte, 8))
	dynamicRoutes.Store(firstRoute, SessionData{
		Stage:     1,
		SessionID: sessionID,
		CreatedAt: time.Now(),
	})

	resp := ApiResponse{
		Success:      true,
		NextEndpoint: firstRoute,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
func handleDynamicRouter(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	val, ok := dynamicRoutes.Load(path)
	if !ok {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	session := val.(SessionData)
	dynamicRoutes.Delete(path)
	if time.Since(session.CreatedAt) > CHALLENGE_EXPIRATION {
		http.Error(w, "Session Expired", http.StatusForbidden)
		return
	}
	switch session.Stage {
	case 1:
		handleStage1Telemetry(w, r, session)
	case 2:
		handleStage2Challenge(w, r, session)
	case 3:
		handleStage3Verify(w, r, session)
	default:
		http.Error(w, "Invalid Session Stage", http.StatusInternalServerError)
	}
}

func handleStage1Telemetry(w http.ResponseWriter, r *http.Request, session SessionData) {
	var req InitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Telemetry.IsWebDriver {
		json.NewEncoder(w).Encode(ApiResponse{Success: false, Error: "WebDriver detected"})
		return
	}
	if req.Telemetry.ScreenWidth == 0 || req.Telemetry.WindowOutWidth == 0 {
		json.NewEncoder(w).Encode(ApiResponse{Success: false, Error: "Headless dimensions"})
		return
	}

	nextRoute := generateRoutePath()
	dynamicRoutes.Store(nextRoute, SessionData{
		Stage:     2,
		SessionID: session.SessionID,
		CreatedAt: session.CreatedAt,
	})

	resp := ApiResponse{
		Success:      true,
		NextEndpoint: nextRoute,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleStage2Challenge(w http.ResponseWriter, r *http.Request, session SessionData) {
	b := make([]byte, 32)
	rand.Read(b)
	challenge := hex.EncodeToString(b)
	exp := time.Now().Add(CHALLENGE_EXPIRATION).Unix()
	obf := hex.EncodeToString(make([]byte, 8))

	canvasSeed := hex.EncodeToString(make([]byte, 4))

	mac := hmac.New(sha256.New, []byte(HMAC_SECRET_KEY))
	mac.Write([]byte(fmt.Sprintf("%s:%d:%s", challenge, exp, obf)))
	signature := hex.EncodeToString(mac.Sum(nil))

	nextRoute := generateRoutePath()

	dynamicRoutes.Store(nextRoute, SessionData{
		Stage:     3,
		SessionID: session.SessionID,
		CreatedAt: session.CreatedAt,
	})

	resp := ChallengeResponse{
		NextEndpoint: nextRoute,
		Challenge:    challenge,
		Difficulty:   POW_DIFFICULTY,
		ExpiresAt:    exp,
		Signature:    signature,
		Obfuscator:   obf,
		CanvasSeed:   canvasSeed,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleStage3Verify(w http.ResponseWriter, r *http.Request, session SessionData) {
	var req SolutionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	mac := hmac.New(sha256.New, []byte(HMAC_SECRET_KEY))
	mac.Write([]byte(fmt.Sprintf("%s:%d:%s", req.Challenge, req.ExpiresAt, req.Obfuscator)))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(req.Signature), []byte(expectedSig)) {
		json.NewEncoder(w).Encode(ApiResponse{Success: false, Error: "Invalid signature"})
		return
	}
	if req.SecurityPayload == "devtools_detected" {
		json.NewEncoder(w).Encode(ApiResponse{Success: false, Error: "DevTools detected"})
		return
	}
	if len(req.CanvasData) < 10 {
		json.NewEncoder(w).Encode(ApiResponse{Success: false, Error: "Canvas missing"})
		return
	}
	data := fmt.Sprintf("%s%s%s%s%s", req.Challenge, req.Nonce, req.Origin, req.Fingerprint, req.CanvasData[:10])
	hash := sha256.Sum256([]byte(data))
	hashHex := hex.EncodeToString(hash[:])
	targetPrefix := strings.Repeat("0", POW_DIFFICULTY)

	if !strings.HasPrefix(hashHex, targetPrefix) {
		json.NewEncoder(w).Encode(ApiResponse{Success: false, Error: "Invalid PoW"})
		return
	}

	claims := jwt.MapClaims{
		"iss":  ISSUER_NAME,
		"orig": req.Origin,
		"fp":   req.Fingerprint,
		"exp":  time.Now().Add(TOKEN_EXPIRATION).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, _ := token.SignedString([]byte(HMAC_SECRET_KEY))

	resp := ApiResponse{
		Success: true,
		Token:   signedToken,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
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

func handleLogin(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(HMAC_SECRET_KEY), nil
	})
	if err != nil || !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
