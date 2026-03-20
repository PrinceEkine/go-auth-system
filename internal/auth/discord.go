package auth

import (
    "net/http"
    "os"

    "golang.org/x/oauth2"
)

var DiscordEndpoint = oauth2.Endpoint{
    AuthURL:  "https://discord.com/api/oauth2/authorize",
    TokenURL: "https://discord.com/api/oauth2/token",
}

var discordConfig = &oauth2.Config{
    ClientID:     os.Getenv("DISCORD_CLIENT_ID"),
    ClientSecret: os.Getenv("DISCORD_CLIENT_SECRET"),
    RedirectURL:  os.Getenv("DISCORD_REDIRECT_URL"), // e.g. https://yourdomain.com/auth/discord/callback
    Scopes:       []string{"identify", "email"},
    Endpoint:     DiscordEndpoint,
}

func DiscordLoginHandler(w http.ResponseWriter, r *http.Request) {
    url := discordConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
    http.Redirect(w, r, url, http.StatusFound)
}

func DiscordCallbackHandler(w http.ResponseWriter, r *http.Request) {
    code := r.URL.Query().Get("code")
    token, err := discordConfig.Exchange(r.Context(), code)
    if err != nil {
        http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
        return
    }

    // Use token.AccessToken (for now just display it)
    w.Write([]byte("Discord login successful! Access Token: " + token.AccessToken))
}
