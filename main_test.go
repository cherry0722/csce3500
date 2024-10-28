package main

import (
    "crypto/rand"
    "crypto/rsa"
    "database/sql"
    "encoding/json"   // Add this line for JSON handling
    "errors"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
    "time"
)


// MockDBInitializer simulates a successful database initialization
type MockDBInitializer struct{}

func (m *MockDBInitializer) InitDB() (*sql.DB, error) {
    return initDB()
}

// MockDBInitializerWithError simulates a failed database initialization
type MockDBInitializerWithError struct{}

func (m *MockDBInitializerWithError) InitDB() (*sql.DB, error) {
    return nil, errors.New("mocked database initialization error")
}

// ClearKeysTable removes all entries from the keys table to ensure a clean state
func ClearKeysTable(db *sql.DB) error {
    _, err := db.Exec("DELETE FROM keys")
    return err
}

// TestInitDB tests successful database initialization
func TestInitDB(t *testing.T) {
    db, err := initDB()
    if err != nil {
        t.Fatalf("Failed to initialize database: %v", err)
    }
    defer db.Close()
}

// TestInitDBFailure simulates a failure in initializing the database
func TestInitDBFailure(t *testing.T) {
    originalDBFile := dbFile
    defer func() { dbFile = originalDBFile }()
    dbFile = "/invalid_path/totally_not_my_privateKeys.db"

    _, err := initDB()
    if err == nil {
        t.Fatal("Expected error for invalid database path, got nil")
    }
}


// TestGetKeyFromDBEmpty verifies error handling when no keys are available
func TestGetKeyFromDBEmpty(t *testing.T) {
    db, _ := initDB()
    defer db.Close()
    ClearKeysTable(db)

    _, err := getKeyFromDB(db, false)
    if err == nil || err.Error() != "no keys available" {
        t.Fatalf("Expected 'no keys available' error, got %v", err)
    }
}


// TestSaveKeyToDBError simulates an error during saveKeyToDB
func TestSaveKeyToDBError(t *testing.T) {
    db, _ := initDB()
    defer db.Close()
    db.Close()
    privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
    err := saveKeyToDB(db, privateKey, time.Now().Add(1*time.Hour))
    if err == nil {
        t.Fatal("Expected error when saving key to closed database, got nil")
    }
}

// TestInitializeServerSuccess tests initializeServer with a successful DB connection
func TestInitializeServerSuccess(t *testing.T) {
    mockInit := &MockDBInitializer{}
    db, err := initializeServer(mockInit)
    if err != nil {
        t.Fatalf("Expected successful initialization, got error: %v", err)
    }
    defer db.Close()
}

// TestInitializeServerFailure tests initializeServer with a failed DB connection
func TestInitializeServerFailure(t *testing.T) {
    mockInit := &MockDBInitializerWithError{}
    _, err := initializeServer(mockInit)
    if err == nil {
        t.Errorf("Expected initialization error, got nil")
    }
}

// TestAuthHandlerNoKeyAvailable tests error handling when no valid keys are available
func TestAuthHandlerNoKeyAvailable(t *testing.T) {
    db, _ := initDB()
    defer db.Close()
    ClearKeysTable(db) // Clear any keys from the table

    req := httptest.NewRequest("POST", "http://localhost:8080/auth", nil)
    w := httptest.NewRecorder()
    handler := authHandler(db)
    handler(w, req)

    res := w.Result()
    if res.StatusCode != http.StatusInternalServerError {
        t.Errorf("Expected status InternalServerError; got %v", res.Status)
    }
    if w.Body.String() != "No key available\n" {
        t.Errorf("Expected 'No key available' message, got: %v", w.Body.String())
    }
}
//th available keys
func TestJwksHandler(t *testing.T) {
    db, _ := initDB()
    defer db.Close()
    generateKey(db, time.Now().Add(1 * time.Hour))

    req := httptest.NewRequest("GET", "http://localhost:8080/.well-known/jwks.json", nil)
    w := httptest.NewRecorder()
    handler := jwksHandler(db)
    handler(w, req)

    res := w.Result()
    if res.StatusCode != http.StatusOK {
        t.Errorf("Expected status OK; got %v", res.Status)
    }
}

// TestJwksHandlerNoKeyAvailable tests the /jwks.json endpoint when no keys are available
func TestJwksHandlerNoKeyAvailable(t *testing.T) {
    db, _ := initDB()
    defer db.Close()
    ClearKeysTable(db)

    req := httptest.NewRequest("GET", "http://localhost:8080/.well-known/jwks.json", nil)
    w := httptest.NewRecorder()
    handler := jwksHandler(db)
    handler(w, req)

    res := w.Result()
    if res.StatusCode != http.StatusInternalServerError {
        t.Errorf("Expected status InternalServerError; got %v", res.Status)
    }
}

// Adjusted TestAuthHandlerTokenStructure to handle specific error messages
func TestAuthHandlerTokenStructure(t *testing.T) {
    db, _ := initDB()
    defer db.Close()
    generateKey(db, time.Now().Add(1 * time.Hour))

    req := httptest.NewRequest("POST", "http://localhost:8080/auth", nil)
    w := httptest.NewRecorder()
    handler := authHandler(db)
    handler(w, req)

    res := w.Result()
    if res.StatusCode != http.StatusOK {
        t.Errorf("Expected status OK; got %v", res.Status)
    }
    token := w.Body.String()
    if !strings.Contains(token, "token") {
        t.Errorf("Expected a valid JWT token format, got: %v", token)
    }
}


// TestBase64UrlEncode checks base64UrlEncode utility
func TestBase64UrlEncode(t *testing.T) {
    data := []byte("test")
    encoded := base64UrlEncode(data)
    expected := "dGVzdA" // Base64 URL-safe encoding of "test"
    if encoded != expected {
        t.Errorf("Expected %s; got %s", expected, encoded)
    }
}




// TestGenerateKeyError simulates generateKey failure on closed DB
func TestGenerateKeyError(t *testing.T) {
    db, _ := initDB()
    defer db.Close()
    db.Close()
    err := generateKey(db, time.Now().Add(1*time.Hour))
    if err == nil {
        t.Fatal("Expected error when generating key with closed database")
    }
}

// Adjusted TestAuthHandlerInvalidTokenFormat to handle consistent error messages
func TestAuthHandlerInvalidTokenFormat(t *testing.T) {
    db, _ := initDB()
    defer db.Close()
    ClearKeysTable(db) // Ensure no keys are present

    req := httptest.NewRequest("POST", "http://localhost:8080/auth?expired=false", nil)
    w := httptest.NewRecorder()
    handler := authHandler(db)
    handler(w, req)

    res := w.Result()
    if res.StatusCode != http.StatusInternalServerError {
        t.Errorf("Expected status InternalServerError; got %v", res.Status)
    }
    if w.Body.String() != "No key available\n" {
        t.Errorf("Expected 'No key available' message, got: %v", w.Body.String())
    }
}

// TestAuthHandlerExpiredKey simulates the issuance of a JWT with an expired key
func TestAuthHandlerExpiredKey(t *testing.T) {
    db, _ := initDB()
    defer db.Close()
    generateKey(db, time.Now().Add(-1 * time.Hour))

    req := httptest.NewRequest("POST", "http://localhost:8080/auth?expired=true", nil)
    w := httptest.NewRecorder()
    handler := authHandler(db)
    handler(w, req)

    res := w.Result()
    if res.StatusCode != http.StatusOK {
        t.Errorf("Expected status OK; got %v", res.Status)
    }
    token := w.Body.String()
    if len(token) < 50 {
        t.Errorf("Expected a JWT token, got: %v", token)
    }
}

// TestJwksHandlerMultipleKeys tests jwksHandler with multiple keys in the database
func TestJwksHandlerMultipleKeys(t *testing.T) {
    db, _ := initDB()
    defer db.Close()
    ClearKeysTable(db) // Ensure a clean state

    // Add two valid keys with different expiration times
    generateKey(db, time.Now().Add(1*time.Hour))
    generateKey(db, time.Now().Add(2*time.Hour))

    req := httptest.NewRequest("GET", "http://localhost:8080/.well-known/jwks.json", nil)
    w := httptest.NewRecorder()
    handler := jwksHandler(db)
    handler(w, req)

    res := w.Result()
    if res.StatusCode != http.StatusOK {
        t.Errorf("Expected status OK; got %v", res.Status)
    }

    // Verify the JWKS structure
    var jwksResponse map[string][]JWK
    err := json.NewDecoder(res.Body).Decode(&jwksResponse)
    if err != nil {
        t.Fatalf("Failed to decode JWKS response: %v", err)
    }

    if len(jwksResponse["keys"]) < 2 {
        t.Error("Expected at least two keys in JWKS response, got fewer")
    }
}

// TestGetKeyFromDBErrorHandling simulates a database retrieval error in getKeyFromDB
func TestGetKeyFromDBErrorHandling(t *testing.T) {
    db, _ := initDB()
    db.Close() // Close the DB to simulate a retrieval error

    _, err := getKeyFromDB(db, false)
    if err == nil {
        t.Fatal("Expected an error due to closed database connection, but got none")
    }
}
