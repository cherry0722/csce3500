package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "database/sql"
    "encoding/base64"
    "encoding/json"
    "encoding/pem"
    "errors"           
    "fmt"
    "log"
    "net/http"
    "time"
    
    "github.com/dgrijalva/jwt-go"
    _ "github.com/mattn/go-sqlite3"
)

var dbFile = "totally_not_my_privateKeys.db"

// JWK represents the JSON Web Key format for public keys
type JWK struct {
    Kid string `json:"kid"`
    Alg string `json:"alg"`
    Kty string `json:"kty"`
    N   string `json:"n"`
    E   string `json:"e"`
}

// DBInitializer interface for initializing the database
type DBInitializer interface {
    InitDB() (*sql.DB, error)
}

// RealDBInitializer connects to SQLite
type RealDBInitializer struct{}

// Implement InitDB method for RealDBInitializer
func (r *RealDBInitializer) InitDB() (*sql.DB, error) {
    return initDB()
}

// Initialize the SQLite database and create the `keys` table if it doesn’t exist
func initDB() (*sql.DB, error) {
    db, err := sql.Open("sqlite3", dbFile)
    if err != nil {
        return nil, err
    }

    createTableSQL := `CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    );`
    _, err = db.Exec(createTableSQL)
    if err != nil {
        return nil, fmt.Errorf("failed to create table: %v", err)
    }
    return db, nil
}

// Serialize and save an RSA private key in the database with an expiration time
func saveKeyToDB(db *sql.DB, privateKey *rsa.PrivateKey, expiry time.Time) error {
    privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
    privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})

    _, err := db.Exec("INSERT INTO keys (key, exp) VALUES (?, ?)", privPEM, expiry.Unix())
    return err
}

// Generate an RSA private key and store it in the database with an expiration time
func generateKey(db *sql.DB, expiry time.Time) error {
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return err
    }
    return saveKeyToDB(db, privateKey, expiry)
}

// Retrieve an RSA private key from the database based on whether it's expired
func getKeyFromDB(db *sql.DB, expired bool) (*rsa.PrivateKey, error) {
    query := "SELECT key FROM keys WHERE exp "
    if expired {
        query += "< ? ORDER BY exp DESC LIMIT 1"
    } else {
        query += "> ? ORDER BY exp ASC LIMIT 1"
    }

    var keyPEM []byte
    err := db.QueryRow(query, time.Now().Unix()).Scan(&keyPEM)
    if err == sql.ErrNoRows { // Specific handling for no rows
        log.Println("No keys found in the database for the specified expiration condition")
        return nil, errors.New("no keys available")
    } else if err != nil {
        return nil, fmt.Errorf("failed to retrieve key: %v", err)
    }

    block, _ := pem.Decode(keyPEM)
    if block == nil || block.Type != "RSA PRIVATE KEY" {
        return nil, fmt.Errorf("failed to decode PEM block containing private key")
    }

    privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        return nil, fmt.Errorf("failed to parse private key: %v", err)
    }

    return privateKey, nil
}




func authHandler(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        expired := r.URL.Query().Get("expired") != ""
        privateKey, err := getKeyFromDB(db, expired)
        if err != nil || privateKey == nil { // Check if no valid key is found
            log.Println("authHandler:", err)
            http.Error(w, "No key available", http.StatusInternalServerError)
            return
        }

        token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
            "exp": time.Now().Add(10 * time.Minute).Unix(),
        })
        tokenString, _ := token.SignedString(privateKey)
        w.Header().Set("Content-Type", "application/json")
        w.Write([]byte(fmt.Sprintf(`{"token": "%s"}`, tokenString)))
    }
}


func jwksHandler(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        rows, err := db.Query("SELECT kid, key FROM keys WHERE exp > ?", time.Now().Unix())
        if err != nil {
            log.Println("jwksHandler: Failed to retrieve keys from the database")
            http.Error(w, "Failed to retrieve keys", http.StatusInternalServerError)
            return
        }
        defer rows.Close()

        var jwks []JWK
        for rows.Next() {
            var kid int
            var keyPEM []byte
            rows.Scan(&kid, &keyPEM)

            block, _ := pem.Decode(keyPEM)
            privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
            jwk := JWK{
                Kid: fmt.Sprintf("%d", kid),
                Alg: "RS256",
                Kty: "RSA",
                N:   base64UrlEncode(privateKey.PublicKey.N.Bytes()),
                E:   "AQAB",
            }
            jwks = append(jwks, jwk)
        }

        if len(jwks) == 0 {
            log.Println("jwksHandler: No keys available for JWKS")
            http.Error(w, "No keys available", http.StatusInternalServerError)
            return
        }

        response, _ := json.Marshal(map[string][]JWK{"keys": jwks})
        w.Header().Set("Content-Type", "application/json")
        w.Write(response)
    }
}



//Helper function to encode RSA modulus in base64 URL-safe format
func base64UrlEncode(data []byte) string {
    return base64.RawURLEncoding.EncodeToString(data)
}

// initializeServer function to use DBInitializer interface
var initializeServer = func(dbInit DBInitializer) (*sql.DB, error) {
    db, err := dbInit.InitDB()
    if err != nil {
        return nil, err
    }

    generateKey(db, time.Now().Add(-1*time.Hour)) // Expired key
    generateKey(db, time.Now().Add(1*time.Hour))   // Valid key
    return db, nil
}

// Main function to set up the server and start listening on port 8080
func main() {
    dbInit := &RealDBInitializer{}
    db, err := initializeServer(dbInit)
    if err != nil {
        log.Fatal("Failed to initialize server:", err)
    }
    defer db.Close()

    // Set up HTTP handlers
    http.HandleFunc("/.well-known/jwks.json", jwksHandler(db))
    http.HandleFunc("/auth", authHandler(db))

    log.Println("Starting server on :8080...")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

