package auth

import (
    "database/sql"
    "net/http"

    "golang.org/x/crypto/bcrypt"
)

// SignupHandler handles user registration
func SignupHandler(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "Invalid request", http.StatusBadRequest)
            return
        }

        email := r.FormValue("email")
        password := r.FormValue("password")

        hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
        if err != nil {
            http.Error(w, "Error hashing password", http.StatusInternalServerError)
            return
        }

        _, err = db.Exec("INSERT INTO users (email, password, provider) VALUES ($1, $2, $3)", email, string(hashed), "local")
        if err != nil {
            http.Error(w, "Error creating user", http.StatusInternalServerError)
            return
        }

        http.Redirect(w, r, "/login", http.StatusSeeOther)
    }
}

// LoginUser validates credentials and returns email if successful
func LoginUser(db *sql.DB, r *http.Request) (string, error) {
    email := r.FormValue("email")
    password := r.FormValue("password")

    var hashed string
    err := db.QueryRow("SELECT password FROM users WHERE email=$1", email).Scan(&hashed)
    if err != nil {
        return "", err
    }

    if bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password)) != nil {
        return "", err
    }

    return email, nil
}
