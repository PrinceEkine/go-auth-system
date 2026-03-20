package main

import (
    "database/sql"
    "html/template"
    "log"
    "net/http"
    "os"

    _ "github.com/lib/pq"
    "go-auth-system/internal/auth"
)

func main() {
    db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Serve static files
    http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

    // Root route
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        tmpl, err := template.ParseFiles("templates/index.html")
        if err != nil {
            http.Error(w, "Template error", http.StatusInternalServerError)
            return
        }
        tmpl.Execute(w, nil)
    })

    // Templates
    http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
        tmpl, err := template.ParseFiles("templates/login.html")
        if err != nil {
            http.Error(w, "Template error", http.StatusInternalServerError)
            return
        }
        tmpl.Execute(w, nil)
    })
    http.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) {
        tmpl, err := template.ParseFiles("templates/signup.html")
        if err != nil {
            http.Error(w, "Template error", http.StatusInternalServerError)
            return
        }
        tmpl.Execute(w, nil)
    })
    http.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
        email, err := auth.ValidateJWT(r)
        if err != nil {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }
        tmpl, err := template.ParseFiles("templates/dashboard.html")
        if err != nil {
            http.Error(w, "Template error", http.StatusInternalServerError)
            return
        }
        tmpl.Execute(w, map[string]string{"Email": email})
    })
    http.HandleFunc("/privacy", func(w http.ResponseWriter, r *http.Request) {
        tmpl, _ := template.ParseFiles("templates/privacy.html")
        tmpl.Execute(w, nil)
    })
    http.HandleFunc("/terms", func(w http.ResponseWriter, r *http.Request) {
        tmpl, _ := template.ParseFiles("templates/terms.html")
        tmpl.Execute(w, nil)
    })

    // Password auth
    http.HandleFunc("/signup-post", auth.SignupHandler(db))
    http.HandleFunc("/login-post", func(w http.ResponseWriter, r *http.Request) {
        email, err := auth.LoginUser(db, r)
        if err != nil {
            http.Error(w, "Invalid credentials", http.StatusUnauthorized)
            return
        }
        token, _ := auth.GenerateJWT(email)
        auth.SetSessionCookie(w, token)
        http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
    })

    // OAuth routes
    http.HandleFunc("/auth/google", auth.GoogleLoginHandler)
    http.HandleFunc("/auth/google/callback", auth.GoogleCallbackHandler)

    http.HandleFunc("/auth/github", auth.GitHubLoginHandler)
    http.HandleFunc("/auth/github/callback", auth.GitHubCallbackHandler)

    http.HandleFunc("/auth/discord", auth.DiscordLoginHandler)
    http.HandleFunc("/auth/discord/callback", auth.DiscordCallbackHandler)

    // Logout
    http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
        cookie := &http.Cookie{
            Name:   "session",
            Value:  "",
            Path:   "/",
            MaxAge: -1,
        }
        http.SetCookie(w, cookie)
        http.Redirect(w, r, "/login", http.StatusSeeOther)
    })

    // Health check
    http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Auth system running..."))
    })

    // Dynamic port (Render sets PORT)
    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }
    log.Println("Server running on :" + port)
    http.ListenAndServe(":"+port, nil)
}
