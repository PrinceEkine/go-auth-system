package auth

import (
    "net/http"
    "os"
    "time"

    "github.com/golang-jwt/jwt/v5"
)

var jwtKey = []byte(os.Getenv("JWT_SECRET"))

func GenerateJWT(email string) (string, error) {
    claims := &jwt.RegisteredClaims{
        Subject:   email,
        ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
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

func ValidateJWT(r *http.Request) (string, error) {
    cookie, err := r.Cookie("session")
    if err != nil {
        return "", err
    }

    token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
        return jwtKey, nil
    })
    if err != nil || !token.Valid {
        return "", err
    }

    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        return "", err
    }

    return claims["sub"].(string), nil
}
