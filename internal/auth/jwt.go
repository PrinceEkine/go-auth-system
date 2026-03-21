package auth

import (
    "net/http"
    "os"
    "time"

    "github.com/golang-jwt/jwt/v5"
)

var jwtKey = []byte(os.Getenv("JWT_SECRET"))

type Claims struct {
    Email    string `json:"email"`
    Provider string `json:"provider"`
    jwt.RegisteredClaims
}

func GenerateJWT(email, provider string) (string, error) {
    expirationTime := time.Now().Add(24 * time.Hour)
    claims := &Claims{
        Email:    email,
        Provider: provider,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(expirationTime),
        },
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(jwtKey)
}

func SetSessionCookie(w http.ResponseWriter, token string) {
    cookie := &http.Cookie{
        Name:     "session",
        Value:    token,
        Path:     "/",
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteLaxMode,
    }
    http.SetCookie(w, cookie)
}

func ValidateJWT(r *http.Request) (string, string, error) {
    cookie, err := r.Cookie("session")
    if err != nil {
        return "", "", err
    }

    claims := &Claims{}
    token, err := jwt.ParseWithClaims(cookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
        return jwtKey, nil
    })
    if err != nil || !token.Valid {
        return "", "", err
    }

    return claims.Email, claims.Provider, nil
}
