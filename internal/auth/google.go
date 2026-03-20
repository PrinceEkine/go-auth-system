package auth

import (
    "context"
    "encoding/json"
    "net/http"

    "golang.org/x/oauth2"
    "golang.org/x/oauth2/google"
)

var GoogleOAuthConfig *oauth2.Config

func InitGoogleOAuth(clientID, clientSecret string) {
    GoogleOAuthConfig = &oauth2.Config{
        RedirectURL:  "http://localhost:8080/auth/google/callback",
        ClientID:     clientID,
        ClientSecret: clientSecret,
        Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
        Endpoint:     google.Endpoint,
    }
}

func GoogleLoginHandler(w http.ResponseWriter, r *http.Request) {
    url := GoogleOAuthConfig.AuthCodeURL("randomstate")
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func GoogleCallbackHandler(w http.ResponseWriter, r *http.Request) {
    code := r.URL.Query().Get("code")
    token, err := GoogleOAuthConfig.Exchange(context.Background(), code)
    if err != nil {
        http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
        return
    }

    client := GoogleOAuthConfig.Client(context.Background(), token)
    resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
    if err != nil {
        http.Error(w, "Failed to get user info", http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    var userInfo map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&userInfo)

    // Issue JWT for this Google user
    email := userInfo["email"].(string)
    jwtToken, _ := GenerateJWT(email)

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"token": jwtToken})
}
