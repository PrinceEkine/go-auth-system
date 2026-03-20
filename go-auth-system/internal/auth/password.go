package auth

import (
    "database/sql"
    "net/http"
    "golang.org/x/crypto/bcrypt"
)

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

func LoginHandler(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "Invalid request", http.StatusBadRequest)
            return
        }

        email := r.FormValue("email")
        password := r.FormValue("password")

        var hashed string
        err := db.QueryRow("SELECT password FROM users WHERE email=$1", email).Scan(&hashed)
        if err != nil {
            http.Error(w, "User not found", http.StatusUnauthorized)
            return
        }

        if bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password)) != nil {
            http.Error(w, "Invalid credentials", http.StatusUnauthorized)
            return
        }

        http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
    }
}
