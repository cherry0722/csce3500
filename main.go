package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// Define the structure of a JSON Web Key (JWK)
type JWK struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// Structure to hold RSA private key, key ID, and expiry time
type Key struct {
	Key    *rsa.PrivateKey
	Kid    string
	Expiry time.Time
}

var keys []Key // Slice to store keys with unique identifiers and expiration

// Generate a new RSA key pair with a unique kid and set an expiry timestamp
func generateKey() {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := fmt.Sprintf("%d", time.Now().Unix()) // Use current timestamp as unique kid
	expiry := time.Now().Add(10 * time.Minute)  // Set key expiration time to 10 minutes from now

	keys = append(keys, Key{Key: privateKey, Kid: kid, Expiry: expiry})
}

// JWKS endpoint: Serves only active (non-expired) public keys in JWKS format
func jwksHandler(w http.ResponseWriter, r *http.Request) {
	var jwks []JWK
	for _, key := range keys {
		if key.Expiry.After(time.Now()) { // Include only active (non-expired) keys
			jwk := JWK{
				Kid: key.Kid,
				Alg: "RS256",
				Kty: "RSA",
				N:   base64UrlEncode(key.Key.PublicKey.N.Bytes()),
				E:   "AQAB", // RSA public exponent (65537 in base64)
			}
			jwks = append(jwks, jwk)
		}
	}
	response, _ := json.Marshal(map[string][]JWK{"keys": jwks})
	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

// Auth endpoint: Issues a JWT using either an active or expired key based on the 'expired' query parameter
func authHandler(w http.ResponseWriter, r *http.Request) {
	expired := r.URL.Query().Get("expired") != ""
	var selectedKey Key

	// Choose a key based on the 'expired' parameter
	for _, k := range keys {
		if (expired && k.Expiry.Before(time.Now())) || (!expired && k.Expiry.After(time.Now())) {
			selectedKey = k
			break
		}
	}

	// Generate JWT token with claims and the selected key
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	})
	token.Header["kid"] = selectedKey.Kid
	tokenString, _ := token.SignedString(selectedKey.Key)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(fmt.Sprintf(`{"token": "%s"}`, tokenString)))
}

// Helper function to encode data in base64 URL-safe format (used for RSA modulus in JWK)
func base64UrlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func main() {
	generateKey() // Generate an initial RSA key pair on server start

	http.HandleFunc("/.well-known/jwks.json", jwksHandler) // JWKS endpoint
	http.HandleFunc("/auth", authHandler)                  // Auth endpoint

	log.Println("Starting server on :8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

