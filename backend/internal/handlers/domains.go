package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type DomainHandler struct {
	DB *pgxpool.Pool
}

type createDomainRequest struct {
	Hostname              string `json:"hostname"`
	CheckIntervalSeconds  int    `json:"check_interval_seconds"`
}

type domainResponse struct {
	ID                   string    `json:"id"`
	Hostname             string    `json:"hostname"`
	CheckIntervalSeconds int       `json:"check_interval_seconds"`
	IsActive             bool      `json:"is_active"`
	CreatedAt            time.Time `json:"created_at"`
}

func (h *DomainHandler) Create(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req createDomainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Hostname == "" {
		http.Error(w, "hostname is required", http.StatusBadRequest)
		return
	}

	if req.CheckIntervalSeconds == 0 {
		req.CheckIntervalSeconds = 300 // 5 minutes
	}

	var resp domainResponse
	err := h.DB.QueryRow(
		context.Background(),
		`INSERT INTO domains (user_id, hostname, check_interval_seconds)
		 VALUES ($1, $2, $3)
		 RETURNING id, hostname, check_interval_seconds, is_active, created_at`,
		userID, req.Hostname, req.CheckIntervalSeconds,
	).Scan(&resp.ID, &resp.Hostname, &resp.CheckIntervalSeconds, &resp.IsActive, &resp.CreatedAt)
	if err != nil {
		respondError(w, "DomainHandler.Create", err, "failed to create domain", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

func (h *DomainHandler) List(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	rows, err := h.DB.Query(
		context.Background(),
		`SELECT id, hostname, check_interval_seconds, is_active, created_at
		 FROM domains WHERE user_id = $1 ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		respondError(w, "DomainHandler.List", err, "failed to fetch domains", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	domainsList := []domainResponse{}
	for rows.Next() {
		var d domainResponse
		if err := rows.Scan(&d.ID, &d.Hostname, &d.CheckIntervalSeconds, &d.IsActive, &d.CreatedAt); err != nil {
			respondError(w, "DomainHandler.List.Scan", err, "failed to read domain data", http.StatusInternalServerError)
			return
		}
		domainsList = append(domainsList, d)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(domainsList)
}