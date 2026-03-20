package auth

import (
    "net/http"
    "github.com/golang-jwt/jwt/v5"
)

// AuthMiddleware protects routes by validating JWT in the session cookie
func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        cookie, err := r.Cookie("session")
        if err != nil {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
            return jwtKey, nil // use jwtKey from jwt.go
        })
        if err != nil || !token.Valid {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        next.ServeHTTP(w, r)
    })
}
