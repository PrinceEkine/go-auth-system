package auth

import (
    "context"
    "log"
    "net/http"
    "os"

    "golang.org/x/oauth2"
    "golang.org/x/oauth2/google"
)

var googleOAuthConfig = &oauth2.Config{
    RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
    ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
    ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
    Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
    Endpoint:     google.Endpoint,
}

func GoogleLoginHandler(w http.ResponseWriter, r *http.Request) {
    url := googleOAuthConfig.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func GoogleCallbackHandler(w http.ResponseWriter, r *http.Request) {
    code := r.URL.Query().Get("code")
    token, err := googleOAuthConfig.Exchange(context.Background(), code)
    if err != nil {
        log.Println("Google OAuth exchange error:", err)
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }
    // Normally you'd fetch user info here
    email := "googleuser@example.com" // placeholder
    jwt, _ := GenerateJWT(email)
    SetSessionCookie(w, jwt)
    http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
