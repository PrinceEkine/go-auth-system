package auth

import (
    "context"
    "encoding/json"
    "log"
    "net/http"
    "os"

    "golang.org/x/oauth2"
)

var discordEndpoint = oauth2.Endpoint{
    AuthURL:  "https://discord.com/api/oauth2/authorize",
    TokenURL: "https://discord.com/api/oauth2/token",
}

var discordOAuthConfig = &oauth2.Config{
    RedirectURL:  os.Getenv("DISCORD_REDIRECT_URL"),
    ClientID:     os.Getenv("DISCORD_CLIENT_ID"),
    ClientSecret: os.Getenv("DISCORD_CLIENT_SECRET"),
    Scopes:       []string{"identify", "email"},
    Endpoint:     discordEndpoint,
}

func DiscordLoginHandler(w http.ResponseWriter, r *http.Request) {
    url := discordOAuthConfig.AuthCodeURL("state-token")
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func DiscordCallbackHandler(w http.ResponseWriter, r *http.Request) {
    code := r.URL.Query().Get("code")
    token, err := discordOAuthConfig.Exchange(context.Background(), code)
    if err != nil {
        log.Println("Discord OAuth exchange error:", err)
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    // Fetch user info from Discord API
    client := discordOAuthConfig.Client(context.Background(), token)
    resp, err := client.Get("https://discord.com/api/users/@me")
    if err != nil {
        log.Println("Error fetching Discord user info:", err)
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }
    defer resp.Body.Close()

    var user struct {
        ID       string `json:"id"`
        Username string `json:"username"`
        Email    string `json:"email"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
        log.Println("Error decoding Discord user JSON:", err)
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    // Use real email if available, otherwise fallback to username
    email := user.Email
    if email == "" {
        email = user.Username + "@discord.local"
    }

    jwt, _ := GenerateJWT(email, "Discord")
    SetSessionCookie(w, jwt)
    http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
