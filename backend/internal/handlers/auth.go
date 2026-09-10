package handlers

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/phiwakonkem/Domain-Traka/backend/internal/auth"
)

type AuthHandler struct {
	DB *pgxpool.Pool
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type authResponse struct {
	Token string `json:"token"`
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		http.Error(w, "email and password are required", http.StatusBadRequest)
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		respondError(w, "Register.HashPassword", err, "failed to process password", http.StatusInternalServerError)
		return
	}

	var userID string
	err = h.DB.QueryRow(
		context.Background(),
		`INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id`,
		req.Email, hash,
	).Scan(&userID)
	if err != nil {
		respondError(w, "Register.InsertUser", err, "could not create user (email may already be in use)", http.StatusConflict)
		return
	}

	token, err := auth.GenerateToken(userID)
	if err != nil {
		respondError(w, "Register.GenerateToken", err, "failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(authResponse{Token: token})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req registerRequest 
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	var userID, hash string
	err := h.DB.QueryRow(
		context.Background(),
		`SELECT id, password_hash FROM users WHERE email = $1`,
		req.Email,
	).Scan(&userID, &hash)
	if err != nil {
		if err == pgx.ErrNoRows {
			http.Error(w, "invalid email or password", http.StatusUnauthorized)
			return
		}
		respondError(w, "Login.QueryUser", err, "something went wrong", http.StatusInternalServerError)
		return
	}

	if !auth.CheckPassword(req.Password, hash) {
		http.Error(w, "invalid email or password", http.StatusUnauthorized)
		return
	}

		if !auth.CheckPassword(req.Password, hash) {
		http.Error(w, "invalid email or password", http.StatusUnauthorized)
		return
	}

	token, err := auth.GenerateToken(userID)
	if err != nil {
		respondError(w, "Login.GenerateToken", err, "failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(authResponse{Token: token})
}