package auth

import (
    "net/http"
    "os"

    "golang.org/x/oauth2"
)

var GitHubEndpoint = oauth2.Endpoint{
    AuthURL:  "https://github.com/login/oauth/authorize",
    TokenURL: "https://github.com/login/oauth/access_token",
}

var githubConfig = &oauth2.Config{
    ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
    ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
    RedirectURL:  os.Getenv("GITHUB_REDIRECT_URL"), // e.g. https://yourdomain.com/auth/github/callback
    Scopes:       []string{"user:email"},
    Endpoint:     GitHubEndpoint,
}

func GitHubLoginHandler(w http.ResponseWriter, r *http.Request) {
    url := githubConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
    http.Redirect(w, r, url, http.StatusFound)
}

func GitHubCallbackHandler(w http.ResponseWriter, r *http.Request) {
    code := r.URL.Query().Get("code")
    token, err := githubConfig.Exchange(r.Context(), code)
    if err != nil {
        http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
        return
    }

    // Use token.AccessToken (for now just display it)
    w.Write([]byte("GitHub login successful! Access Token: " + token.AccessToken))
}
