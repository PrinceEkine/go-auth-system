package auth

import (
    "context"
    "encoding/json"
    "net/http"

    "golang.org/x/oauth2"
    "golang.org/x/oauth2/github"
)

var GitHubOAuthConfig *oauth2.Config

func InitGitHubOAuth(clientID, clientSecret string) {
    GitHubOAuthConfig = &oauth2.Config{
        RedirectURL:  "http://localhost:8080/auth/github/callback",
        ClientID:     clientID,
        ClientSecret: clientSecret,
        Scopes:       []string{"user:email"},
        Endpoint:     github.Endpoint,
    }
}

func GitHubLoginHandler(w http.ResponseWriter, r *http.Request) {
    url := GitHubOAuthConfig.AuthCodeURL("randomstate")
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func GitHubCallbackHandler(w http.ResponseWriter, r *http.Request) (string, string, error) {
    code := r.URL.Query().Get("code")
    token, err := GitHubOAuthConfig.Exchange(context.Background(), code)
    if err != nil {
        return "", "", err
    }

    client := GitHubOAuthConfig.Client(context.Background(), token)
    resp, err := client.Get("https://api.github.com/user/emails")
    if err != nil {
        return "", "", err
    }
    defer resp.Body.Close()

    var emails []map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&emails)

    var email string
    for _, e := range emails {
        if primary, ok := e["primary"].(bool); ok && primary {
            email = e["email"].(string)
            break
        }
    }

    jwtToken, _ := GenerateJWT(email)
    return email, jwtToken, nil
}
