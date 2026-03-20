package auth

import (
    "net/http"
    "os"
    "golang.org/x/oauth2"
    "golang.org/x/oauth2/discord"
)

var discordOauthConfig = &oauth2.Config{
    RedirectURL:  "https://go-auth-system-tv35.onrender.com/auth/discord/callback",
    ClientID:     os.Getenv("DISCORD_CLIENT_ID"),
    ClientSecret: os.Getenv("DISCORD_CLIENT_SECRET"),
    Scopes:       []string{"identify", "email"},
    Endpoint:     discord.Endpoint,
}

func DiscordLoginHandler(w http.ResponseWriter, r *http.Request) {
    url := discordOauthConfig.AuthCodeURL("state")
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func DiscordCallbackHandler(w http.ResponseWriter, r *http.Request) {
    code := r.URL.Query().Get("code")
    token, err := discordOauthConfig.Exchange(r.Context(), code)
    if err != nil {
        http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
        return
    }
    // TODO: fetch user info from Discord API using token.AccessToken
    http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
