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
        log.Fatal("Database connection error:", err)
    }
    defer db.Close()

    // Serve static files
    http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

    // Public pages
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        renderTemplate(w, "index.html", nil)
    })
    http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
        renderTemplate(w, "login.html", nil)
    })
    http.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) {
        renderTemplate(w, "signup.html", nil)
    })
    http.HandleFunc("/terms", func(w http.ResponseWriter, r *http.Request) {
        renderTemplate(w, "terms.html", nil)
    })
    http.HandleFunc("/privacy", func(w http.ResponseWriter, r *http.Request) {
        renderTemplate(w, "privacy.html", nil)
    })

    // Dashboard
    http.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
        email, provider, err := auth.ValidateJWT(r)
        if err != nil {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }
        renderTemplate(w, "dashboard.html", map[string]string{
            "Email":    email,
            "Provider": provider,
        })
    })

    // Profile
    http.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
        email, provider, err := auth.ValidateJWT(r)
        if err != nil {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }
        renderTemplate(w, "profile.html", map[string]string{
            "Email":    email,
            "Provider": provider,
            "JoinDate": "March 2026", // Replace with DB value if available
        })
    })

    // Settings page
    http.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
        email, provider, err := auth.ValidateJWT(r)
        if err != nil {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }
        renderTemplate(w, "settings.html", map[string]interface{}{
            "Email":    email,
            "Provider": provider,
            "Success":  false,
            "Error":    "",
        })
    })

    // Settings form submission
    http.HandleFunc("/update-settings", func(w http.ResponseWriter, r *http.Request) {
        email, provider, err := auth.ValidateJWT(r)
        if err != nil {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }

        if r.Method == http.MethodPost {
            newPassword := r.FormValue("new_password")
            notifications := r.FormValue("notifications")

            err := auth.UpdateSettings(db, email, newPassword, notifications)
            if err != nil {
                renderTemplate(w, "settings.html", map[string]interface{}{
                    "Email":    email,
                    "Provider": provider,
                    "Success":  false,
                    "Error":    "Failed to update settings. Please try again.",
                })
                return
            }

            renderTemplate(w, "settings.html", map[string]interface{}{
                "Email":    email,
                "Provider": provider,
                "Success":  true,
                "Error":    "",
            })
        } else {
            http.Redirect(w, r, "/settings", http.StatusSeeOther)
        }
    })

    // Password auth
    http.HandleFunc("/signup-post", auth.SignupHandler(db))
    http.HandleFunc("/login-post", func(w http.ResponseWriter, r *http.Request) {
        email, err := auth.LoginUser(db, r)
        if err != nil {
            http.Error(w, "Invalid credentials", http.StatusUnauthorized)
            return
        }
        token, _ := auth.GenerateJWT(email, "Password")
        auth.SetSessionCookie(w, token)
        http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
    })

    // OAuth routes
    http.HandleFunc("/auth/google", auth.GoogleLoginHandler)
    http.HandleFunc("/auth/google/callback", func(w http.ResponseWriter, r *http.Request) {
        email := auth.GoogleCallbackHandler(w, r)
        if email != "" {
            token, _ := auth.GenerateJWT(email, "Google")
            auth.SetSessionCookie(w, token)
            http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
        }
    })

    http.HandleFunc("/auth/github", auth.GitHubLoginHandler)
    http.HandleFunc("/auth/github/callback", func(w http.ResponseWriter, r *http.Request) {
        email := auth.GitHubCallbackHandler(w, r)
        if email != "" {
            token, _ := auth.GenerateJWT(email, "GitHub")
            auth.SetSessionCookie(w, token)
            http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
        }
    })

    http.HandleFunc("/auth/discord", auth.DiscordLoginHandler)
    http.HandleFunc("/auth/discord/callback", func(w http.ResponseWriter, r *http.Request) {
        email := auth.DiscordCallbackHandler(w, r)
        if email != "" {
            token, _ := auth.GenerateJWT(email, "Discord")
            auth.SetSessionCookie(w, token)
            http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
        }
    })

    // Logout
    http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
        cookie := &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1}
        http.SetCookie(w, cookie)
        http.Redirect(w, r, "/login", http.StatusSeeOther)
    })

    // Health check
    http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Auth system running..."))
    })

    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }
    log.Println("Server running on :" + port)
    http.ListenAndServe(":"+port, nil)
}

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
