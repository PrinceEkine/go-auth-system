package auth

import (
    "context"
    "log"
    "net/http"
    "os"

    "golang.org/x/oauth2"
    "golang.org/x/oauth2/github"
)

var githubOAuthConfig = &oauth2.Config{
    RedirectURL:  os.Getenv("GITHUB_REDIRECT_URL"),
    ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
    ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
    Scopes:       []string{"user:email"},
    Endpoint:     github.Endpoint,
}

func GitHubLoginHandler(w http.ResponseWriter, r *http.Request) {
    url := githubOAuthConfig.AuthCodeURL("state-token")
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func GitHubCallbackHandler(w http.ResponseWriter, r *http.Request) {
    code := r.URL.Query().Get("code")
    token, err := githubOAuthConfig.Exchange(context.Background(), code)
    if err != nil {
        log.Println("GitHub OAuth exchange error:", err)
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }
    email := "githubuser@example.com" // placeholder
    jwt, _ := GenerateJWT(email)
    SetSessionCookie(w, jwt)
    http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
