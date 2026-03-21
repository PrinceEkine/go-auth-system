package auth

import (
    "context"
    "encoding/json"
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

    // Fetch user info from Google API
    client := googleOAuthConfig.Client(context.Background(), token)
    resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
    if err != nil {
        log.Println("Error fetching Google user info:", err)
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }
    defer resp.Body.Close()

    var user struct {
        Email string `json:"email"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
        log.Println("Error decoding Google user JSON:", err)
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    email := user.Email
    if email == "" {
        email = "googleuser@example.com"
    }

    jwt, _ := GenerateJWT(email)
    SetSessionCookie(w, jwt)
    http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
