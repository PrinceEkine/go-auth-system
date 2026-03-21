package auth

import (
    "database/sql"
    "net/http"

    "golang.org/x/crypto/bcrypt"
)

// SignupHandler registers a new user
func SignupHandler(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        email := r.FormValue("email")
        password := r.FormValue("password")

        hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
        if err != nil {
            http.Error(w, "Error creating account", http.StatusInternalServerError)
            return
        }

        _, err = db.Exec("INSERT INTO users (email, password) VALUES ($1, $2)", email, string(hashed))
        if err != nil {
            http.Error(w, "Error saving user", http.StatusInternalServerError)
            return
        }

        http.Redirect(w, r, "/login", http.StatusSeeOther)
    }
}

// LoginUser authenticates a user
func LoginUser(db *sql.DB, r *http.Request) (string, error) {
    email := r.FormValue("email")
    password := r.FormValue("password")

    var hashed string
    err := db.QueryRow("SELECT password FROM users WHERE email=$1", email).Scan(&hashed)
    if err != nil {
        return "", err
    }

    err = bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password))
    if err != nil {
        return "", err
    }

    return email, nil
}

// UpdateSettings updates password and notification preferences
func UpdateSettings(db *sql.DB, email, newPassword, notifications string) error {
    if newPassword != "" {
        hashed, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
        if err != nil {
            return err
        }
        _, err = db.Exec("UPDATE users SET password=$1 WHERE email=$2", string(hashed), email)
        if err != nil {
            return err
        }
    }

    if notifications != "" {
        _, err := db.Exec("UPDATE users SET notifications=$1 WHERE email=$2", notifications, email)
        if err != nil {
            return err
        }
    }

    return nil
}
