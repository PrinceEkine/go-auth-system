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
    // Connect to Postgres
    db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
    if err != nil {
        log.Fatal("Database connection error:", err)
    }
    defer db.Close()

    // Serve static files (CSS, JS, images)
    http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

    // Root route (homepage)
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        renderTemplate(w, "index.html", nil)
    })

    // Login page
    http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
        renderTemplate(w, "login.html", nil)
    })

    // Signup page
    http.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) {
        renderTemplate(w, "signup.html", nil)
    })

    // Dashboard (requires JWT)
    http.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
        email, err := auth.ValidateJWT(r)
        if err != nil {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }
        renderTemplate(w, "dashboard.html", map[string]string{"Email": email})
    })

    // Privacy & Terms
    http.HandleFunc("/privacy", func(w http.ResponseWriter, r *http.Request) {
        renderTemplate(w, "privacy.html", nil)
    })
    http.HandleFunc("/terms", func(w http.ResponseWriter, r *http.Request) {
        renderTemplate(w, "terms.html", nil)
    })

    // Password auth handlers
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

// Helper function to render templates safely
func renderTemplate(w http.ResponseWriter, filename string, data interface{}) {
    tmpl, err := template.ParseFiles("templates/" + filename)
    if err != nil {
        log.Println("Template load error:", err)
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }
    err = tmpl.Execute(w, data)
    if err != nil {
        log.Println("Template execution error:", err)
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
    }
}
