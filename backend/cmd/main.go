package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
	"github.com/phiwakonkem/Domain-Traka/backend/internal/db"
	"github.com/phiwakonkem/Domain-Traka/backend/internal/handlers"
	"github.com/phiwakonkem/Domain-Traka/backend/internal/checker"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, relying on system environment variables")
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL is not set")
	}

	pool, err := db.NewPool(context.Background(), dbURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer pool.Close()

	authHandler := &handlers.AuthHandler{DB: pool}
	domainHandler := &handlers.DomainHandler{DB: pool}

	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.Post("/register", authHandler.Register)
	r.Post("/login", authHandler.Login)

	r.Group(func(r chi.Router) {
		r.Use(handlers.RequireAuth)
		r.Post("/domains", domainHandler.Create)
		r.Get("/domains", domainHandler.List)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Domain Traka backend running on :%s", port)

    scheduler := checker.NewScheduler(pool)
	go scheduler.Run(context.Background())

	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal(err)
	}
}