package checker

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type watchedDomain struct {
	ID                   string
	Hostname             string
	CheckIntervalSeconds int
	cancel               context.CancelFunc
}

type Scheduler struct {
	db      *pgxpool.Pool
	mu      sync.Mutex
	watched map[string]*watchedDomain 
}

func NewScheduler(db *pgxpool.Pool) *Scheduler {
	return &Scheduler{
		db:      db,
		watched: make(map[string]*watchedDomain),
	}
}

func (s *Scheduler) Run(ctx context.Context) {
	s.refreshDomains(ctx)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.refreshDomains(ctx)
		case <-ctx.Done():
			log.Println("Scheduler shutting down")
			s.stopAll()
			return
		}
	}
}

func (s *Scheduler) refreshDomains(ctx context.Context) {
	rows, err := s.db.Query(ctx,
		`SELECT id, hostname, check_interval_seconds FROM domains WHERE is_active = true`)
	if err != nil {
		log.Printf("ERROR [Scheduler.refreshDomains]: %v", err)
		return
	}
	defer rows.Close()

	currentIDs := make(map[string]bool)

	for rows.Next() {
		var id, hostname string
		var interval int
		if err := rows.Scan(&id, &hostname, &interval); err != nil {
			log.Printf("ERROR [Scheduler.refreshDomains.Scan]: %v", err)
			continue
		}
		currentIDs[id] = true

		s.mu.Lock()
		_, alreadyWatched := s.watched[id]
		s.mu.Unlock()

		if !alreadyWatched {
			s.startWatching(ctx, id, hostname, interval)
		}
	}

	s.mu.Lock()
	for id, wd := range s.watched {
		if !currentIDs[id] {
			wd.cancel()
			delete(s.watched, id)
			log.Printf("Stopped watching domain: %s", wd.Hostname)
		}
	}
	s.mu.Unlock()
}

func (s *Scheduler) startWatching(parentCtx context.Context, id, hostname string, intervalSeconds int) {
	ctx, cancel := context.WithCancel(parentCtx)

	wd := &watchedDomain{
		ID:                   id,
		Hostname:             hostname,
		CheckIntervalSeconds: intervalSeconds,
		cancel:               cancel,
	}

	s.mu.Lock()
	s.watched[id] = wd
	s.mu.Unlock()

	log.Printf("Started watching domain: %s (every %ds)", hostname, intervalSeconds)

	go s.runUptimeLoop(ctx, wd)
	go s.runCertLoop(ctx, wd)
}

func (s *Scheduler) runUptimeLoop(ctx context.Context, wd *watchedDomain) {
	ticker := time.NewTicker(time.Duration(wd.CheckIntervalSeconds) * time.Second)
	defer ticker.Stop()

	for {
		select {
			case <-ticker.C:
			result := CheckUptime(wd.Hostname)
			s.saveUptimeCheck(ctx, wd.ID, result)
			s.evaluateIncident(ctx, wd.ID)
		case <-ctx.Done():
			return
		}
	}
}

func (s *Scheduler) runCertLoop(ctx context.Context, wd *watchedDomain) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	s.runCertChecks(ctx, wd)

	for {
		select {
		case <-ticker.C:
			s.runCertChecks(ctx, wd)
		case <-ctx.Done():
			return
		}
	}
}

func (s *Scheduler) runCertChecks(ctx context.Context, wd *watchedDomain) {
	sslResult := CheckSSL(wd.Hostname)
	s.saveSSLCheck(ctx, wd.ID, sslResult)

	whoisResult := CheckWHOIS(wd.Hostname)
	s.saveWHOISCheck(ctx, wd.ID, whoisResult)
}

func (s *Scheduler) stopAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, wd := range s.watched {
		wd.cancel()
	}
	s.watched = make(map[string]*watchedDomain)
}

func (s *Scheduler) saveUptimeCheck(ctx context.Context, domainID string, result UptimeResult) {
	_, err := s.db.Exec(ctx,
		`INSERT INTO checks (domain_id, check_type, is_success, status_code, response_time_ms, error_message)
		 VALUES ($1, 'uptime', $2, $3, $4, $5)`,
		domainID, result.IsSuccess, nullableInt(result.StatusCode), nullableInt(result.ResponseTimeMs), result.ErrorMessage)
	if err != nil {
		log.Printf("ERROR [Scheduler.saveUptimeCheck]: %v", err)
	}
}

func (s *Scheduler) saveSSLCheck(ctx context.Context, domainID string, result SSLResult) {
	var expiresAt interface{}
	if result.IsSuccess {
		expiresAt = result.ExpiresAt
	}

	_, err := s.db.Exec(ctx,
		`INSERT INTO checks (domain_id, check_type, is_success, expires_at, error_message)
		 VALUES ($1, 'ssl', $2, $3, $4)`,
		domainID, result.IsSuccess, expiresAt, result.ErrorMessage)
	if err != nil {
		log.Printf("ERROR [Scheduler.saveSSLCheck]: %v", err)
	}
}

func (s *Scheduler) saveWHOISCheck(ctx context.Context, domainID string, result WHOISResult) {
	var expiresAt interface{}
	if result.IsSuccess {
		expiresAt = result.ExpiresAt
	}

	_, err := s.db.Exec(ctx,
		`INSERT INTO checks (domain_id, check_type, is_success, expires_at, error_message)
		 VALUES ($1, 'whois', $2, $3, $4)`,
		domainID, result.IsSuccess, expiresAt, result.ErrorMessage)
	if err != nil {
		log.Printf("ERROR [Scheduler.saveWHOISCheck]: %v", err)
	}
}

func nullableInt(n int) interface{} {
	if n == 0 {
		return nil
	}
	return n
}

const consecutiveFailuresForIncident = 2

func (s *Scheduler) evaluateIncident(ctx context.Context, domainID string) {
	rows, err := s.db.Query(ctx,
		`SELECT is_success FROM checks
		 WHERE domain_id = $1 AND check_type = 'uptime'
		 ORDER BY checked_at DESC
		 LIMIT $2`,
		domainID, consecutiveFailuresForIncident)
	if err != nil {
		log.Printf("ERROR [Scheduler.evaluateIncident.Query]: %v", err)
		return
	}
	defer rows.Close()

	var recentResults []bool
	for rows.Next() {
		var success bool
		if err := rows.Scan(&success); err != nil {
			log.Printf("ERROR [Scheduler.evaluateIncident.Scan]: %v", err)
			return
		}
		recentResults = append(recentResults, success)
	}

	openIncidentID, hasOpenIncident := s.getOpenIncident(ctx, domainID)

	allRecentFailed := len(recentResults) == consecutiveFailuresForIncident
	for _, success := range recentResults {
		if success {
			allRecentFailed = false
			break
		}
	}

	switch {
	case allRecentFailed && !hasOpenIncident:
		s.openIncident(ctx, domainID)

	case len(recentResults) > 0 && recentResults[0] && hasOpenIncident:
		s.resolveIncident(ctx, openIncidentID)
	}
}

func (s *Scheduler) getOpenIncident(ctx context.Context, domainID string) (string, bool) {
	var id string
	err := s.db.QueryRow(ctx,
		`SELECT id FROM incidents WHERE domain_id = $1 AND resolved_at IS NULL
		 ORDER BY started_at DESC LIMIT 1`,
		domainID,
	).Scan(&id)
	if err != nil {
		return "", false
	}
	return id, true
}

func (s *Scheduler) openIncident(ctx context.Context, domainID string) {
	_, err := s.db.Exec(ctx,
		`INSERT INTO incidents (domain_id, reason) VALUES ($1, $2)`,
		domainID, "Uptime check failed twice in a row")
	if err != nil {
		log.Printf("ERROR [Scheduler.openIncident]: %v", err)
		return
	}
	log.Printf("INCIDENT OPENED for domain %s", domainID)
}

func (s *Scheduler) resolveIncident(ctx context.Context, incidentID string) {
	_, err := s.db.Exec(ctx,
		`UPDATE incidents SET resolved_at = now() WHERE id = $1`,
		incidentID)
	if err != nil {
		log.Printf("ERROR [Scheduler.resolveIncident]: %v", err)
		return
	}
	log.Printf("INCIDENT RESOLVED: %s", incidentID)
}