package auth

import (
    "context"
    "encoding/json"
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

    // Fetch user emails from GitHub API
    client := githubOAuthConfig.Client(context.Background(), token)
    resp, err := client.Get("https://api.github.com/user/emails")
    if err != nil {
        log.Println("Error fetching GitHub user emails:", err)
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }
    defer resp.Body.Close()

    var emails []struct {
        Email   string `json:"email"`
        Primary bool   `json:"primary"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
        log.Println("Error decoding GitHub emails JSON:", err)
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    // Pick primary email if available
    email := "githubuser@example.com"
    for _, e := range emails {
        if e.Primary {
            email = e.Email
            break
        }
    }

    jwt, _ := GenerateJWT(email)
    SetSessionCookie(w, jwt)
    http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
