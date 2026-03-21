package auth

import (
    "context"
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

    // TODO: fetch real user info from Discord API using token.AccessToken
    email := "discorduser@example.com" // placeholder

    jwt, _ := GenerateJWT(email)
    SetSessionCookie(w, jwt)
    http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
