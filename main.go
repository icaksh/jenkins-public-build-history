package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	appdb "github.com/icaksh/jenkins-public-build-history/db"
	"github.com/icaksh/jenkins-public-build-history/jenkins"
	"github.com/spf13/viper"
)

var tmpl *template.Template

func templateGlobPath() string {
	if matches, _ := filepath.Glob("templates/*.html"); len(matches) > 0 {
		return "templates/*.html"
	}
	exePath, err := os.Executable()
	if err != nil {
		return "templates/*.html"
	}
	return filepath.Join(filepath.Dir(exePath), "templates", "*.html")
}

// ── Admin session (signed cookie) ─────────────────────────────────────────

func newOpaqueToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func newSession() (string, error) {
	token, err := newOpaqueToken()
	if err != nil {
		return "", err
	}
	expiresAt := time.Now().Add(12 * time.Hour).Unix()
	payload := fmt.Sprintf("%d:%s", expiresAt, token)
	return payload + ":" + signSession(payload), nil
}

func signSession(payload string) string {
	mac := hmac.New(sha256.New, []byte(sessionSecret()))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func sessionSecret() string {
	if secret := viper.GetString("SESSION_SECRET"); secret != "" {
		return secret
	}
	return viper.GetString("ADMIN_PASSWORD")
}

func validSession(r *http.Request) bool {
	c, err := r.Cookie("admin_token")
	if err != nil {
		return false
	}
	expiresAt, _, ok := parseSignedToken(c.Value)
	if !ok {
		return false
	}
	return time.Now().Unix() < expiresAt
}

func parseSignedToken(token string) (int64, string, bool) {
	parts := strings.Split(token, ":")
	if len(parts) != 3 {
		return 0, "", false
	}
	payload := parts[0] + ":" + parts[1]
	if !hmac.Equal([]byte(parts[2]), []byte(signSession(payload))) {
		return 0, "", false
	}
	expiresAt, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, "", false
	}
	return expiresAt, parts[1], true
}

func newAccessSession(code string) (string, error) {
	expiresAt := time.Now().Add(30 * 24 * time.Hour).Unix()
	payload := fmt.Sprintf("%d:%s", expiresAt, hex.EncodeToString([]byte(code)))
	return payload + ":" + signSession(payload), nil
}

func accessCodeFromRequest(r *http.Request) string {
	if code := strings.TrimSpace(r.URL.Query().Get("code")); code != "" {
		return code
	}
	c, err := r.Cookie("access_token")
	if err != nil {
		return ""
	}
	expiresAt, encodedCode, ok := parseSignedToken(c.Value)
	if !ok || time.Now().Unix() >= expiresAt {
		return ""
	}
	rawCode, err := hex.DecodeString(encodedCode)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(rawCode))
}

func setAccessCodeCookie(w http.ResponseWriter, r *http.Request, code string) {
	token, err := newAccessSession(code)
	if err != nil {
		slog.Error("access session creation failed", "error", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   60 * 60 * 24 * 30,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
}

func clearAccessCodeCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
}

func csrfToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie("csrf_token"); err == nil && c.Value != "" {
		return c.Value
	}
	token, err := newOpaqueToken()
	if err != nil {
		slog.Error("csrf token creation failed", "error", err)
		return ""
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		MaxAge:   60 * 60 * 24 * 30,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
	return token
}

func validCSRF(r *http.Request) bool {
	c, err := r.Cookie("csrf_token")
	if err != nil || c.Value == "" {
		return false
	}
	token := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
	if token == "" {
		token = strings.TrimSpace(r.FormValue("csrf_token"))
	}
	return token != "" && hmac.Equal([]byte(token), []byte(c.Value))
}

func validSameOrigin(r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return true
	}
	allowedHosts := []string{r.Host}
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); forwarded != "" {
		allowedHosts = append(allowedHosts, forwarded)
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" {
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return slices.Contains(allowedHosts, u.Host)
	}
	referer := strings.TrimSpace(r.Header.Get("Referer"))
	if referer != "" {
		u, err := url.Parse(referer)
		if err != nil {
			return false
		}
		return slices.Contains(allowedHosts, u.Host)
	}
	return false
}

func rejectIfInvalidMutation(w http.ResponseWriter, r *http.Request) bool {
	if !validSameOrigin(r) || !validCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return true
	}
	return false
}

// ── Config ────────────────────────────────────────────────────────────────

func initConfig() {
	viper.SetConfigFile(".env")
	viper.AutomaticEnv()

	viper.SetDefault("JENKINS_URL", "http://localhost:8080")
	viper.SetDefault("JENKINS_USER", "")
	viper.SetDefault("JENKINS_TOKEN", "")
	viper.SetDefault("PORT", "3000")
	viper.SetDefault("BUILD_LIMIT", 10)
	viper.SetDefault("NOTIFY_POLL_INTERVAL", "10s")
	viper.SetDefault("ADMIN_PASSWORD", "admin")
	viper.SetDefault("SESSION_SECRET", "")
	viper.SetDefault("HOOK_ENCRYPTION_KEY", "")
	viper.SetDefault("DB_PATH", "data.db")
	viper.SetDefault("APP_NAME", "Build History")
	viper.SetDefault("APP_DESCRIPTION", "Jenkins read-only external workspace")
	viper.SetDefault("APP_ICON", "fa-solid fa-hammer")
	viper.SetDefault("APP_LOGO_URL", "")

	if err := viper.ReadInConfig(); err != nil {
		slog.Warn("could not read .env, using env vars / defaults", "error", err)
	} else {
		slog.Info("config loaded", "file", viper.ConfigFileUsed())
	}
	if viper.GetString("ADMIN_PASSWORD") == "admin" {
		slog.Warn("ADMIN_PASSWORD is default 'admin' — please change it")
	}
	if viper.GetString("SESSION_SECRET") == "" {
		slog.Warn("SESSION_SECRET is not set; falling back to ADMIN_PASSWORD for signing admin sessions")
	}
	if viper.GetString("HOOK_ENCRYPTION_KEY") == "" {
		slog.Warn("HOOK_ENCRYPTION_KEY is not set; falling back to SESSION_SECRET for hook encryption")
	}
}

func appBranding() map[string]any {
	return map[string]any{
		"AppName":        viper.GetString("APP_NAME"),
		"AppDescription": viper.GetString("APP_DESCRIPTION"),
		"AppIcon":        viper.GetString("APP_ICON"),
		"AppLogoURL":     viper.GetString("APP_LOGO_URL"),
	}
}

func withTemplateDefaults(data any) any {
	m, ok := data.(map[string]any)
	if !ok {
		return data
	}
	out := make(map[string]any, len(m)+4)
	for key, value := range appBranding() {
		out[key] = value
	}
	for key, value := range m {
		out[key] = value
	}
	return out
}

// ── Path access helpers ───────────────────────────────────────────────────

func isPathAllowed(requestedPath string, allowed []appdb.CodePath) bool {
	for _, a := range allowed {
		if requestedPath == a.Path ||
			strings.HasPrefix(requestedPath, a.Path+"/") ||
			strings.HasPrefix(a.Path, requestedPath+"/") {
			return true
		}
	}
	return false
}

func filterJobs(jobs []jenkins.Job, folderPath string, allowed []appdb.CodePath) []jenkins.Job {
	var out []jenkins.Job
	for _, j := range jobs {
		full := j.Name
		if folderPath != "" {
			full = folderPath + "/" + j.Name
		}
		if isPathAllowed(full, allowed) {
			out = append(out, j)
		}
	}
	return out
}

type runningJob struct {
	Name     string
	FullPath string
}

func runningJobs(jobs []jenkins.Job, folderPath string) []runningJob {
	var out []runningJob
	for _, j := range jobs {
		if j.IsFolder() || !strings.Contains(j.Color, "anime") {
			continue
		}
		fullPath := j.Name
		if folderPath != "" {
			fullPath = folderPath + "/" + j.Name
		}
		out = append(out, runningJob{
			Name:     j.Name,
			FullPath: fullPath,
		})
	}
	return out
}

func collectRunningJobsRecursive(client *jenkins.Client, folderPath string, allowed []appdb.CodePath) ([]runningJob, error) {
	jobs, err := client.GetJobsInFolder(folderPath)
	if err != nil {
		return nil, err
	}

	filtered := filterJobs(jobs, folderPath, allowed)
	out := runningJobs(filtered, folderPath)

	for _, j := range filtered {
		if !j.IsFolder() {
			continue
		}
		nextPath := j.Name
		if folderPath != "" {
			nextPath = folderPath + "/" + j.Name
		}
		nested, err := collectRunningJobsRecursive(client, nextPath, allowed)
		if err != nil {
			slog.Warn("recursive running-jobs scan skipped folder", "path", nextPath, "error", err)
			continue
		}
		out = append(out, nested...)
	}

	return out, nil
}

// ── Main ──────────────────────────────────────────────────────────────────

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)

	initConfig()

	hookSecret := viper.GetString("HOOK_ENCRYPTION_KEY")
	if hookSecret == "" {
		hookSecret = sessionSecret()
	}

	database, err := appdb.New(viper.GetString("DB_PATH"), hookSecret)
	if err != nil {
		slog.Error("db init failed", "error", err)
		os.Exit(1)
	}
	slog.Info("database ready", "path", viper.GetString("DB_PATH"))

	funcMap := template.FuncMap{
		"isEven":   func(i int) bool { return i%2 == 0 },
		"contains": strings.Contains,
		"gt":       func(a, b int) bool { return a > b },
		"add":      func(a, b int) int { return a + b },
		"sub":      func(a, b int) int { return a - b },
		"last":     func(i, total int) bool { return i == total-1 },
		"fmtDate": func(t time.Time) string {
			if t.IsZero() {
				return "-"
			}
			return t.Format("02 Jan 2006")
		},
		"fmtDateTime": func(t time.Time) string {
			if t.IsZero() {
				return "-"
			}
			return t.Format("02 Jan 2006 15:04:05")
		},
		"fmtBuildTime": func(t time.Time) string {
			if t.IsZero() {
				return "-"
			}
			return t.Format("02 Jan 2006, 15:04")
		},
	}
	tmpl = template.Must(
		template.New("").Funcs(funcMap).ParseGlob(templateGlobPath()),
	)

	client := jenkins.New(
		viper.GetString("JENKINS_URL"),
		viper.GetString("JENKINS_USER"),
		viper.GetString("JENKINS_TOKEN"),
	)
	startWebhookNotifier(client, database)

	mux := http.NewServeMux()

	// Public
	mux.HandleFunc("/", handleIndex(client, database))
	mux.HandleFunc("/hooks", handleUserHooks(client, database))
	mux.HandleFunc("/hooks/", handleUserHookDelete(database))
	mux.HandleFunc("/hooks/logs", handleUserHookLogs(database))
	mux.HandleFunc("/hooks/logs-stream", handleUserHookLogsStream(database))
	mux.HandleFunc("/log/", handleLog(client, database))
	mux.HandleFunc("/log-stream/", handleLogStream(client, database))
	mux.HandleFunc("/job-stream/", handleJobStream(client, database))
	mux.HandleFunc("/running-stream", handleRunningStream(client, database))

	// Admin
	mux.HandleFunc("/admin", handleAdmin(client, database))
	mux.HandleFunc("/admin/audit", handleAdminAudit(database))
	mux.HandleFunc("/admin/login", handleAdminLogin(database))
	mux.HandleFunc("/admin/logout", handleAdminLogout(database))
	mux.HandleFunc("/admin/codes", handleAdminCodes(database))
	mux.HandleFunc("/admin/codes/", handleAdminCodesSub(database))
	mux.HandleFunc("/admin/paths/", handleAdminPaths(database))
	mux.HandleFunc("/admin/picker", handleAdminPicker(client))

	addr := ":" + viper.GetString("PORT")
	slog.Info("server started", "addr", addr, "jenkins_url", viper.GetString("JENKINS_URL"))
	if err := http.ListenAndServe(addr, mux); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

// ── Public handlers ───────────────────────────────────────────────────────

// GET /  →  code entry form or remembered session
// GET /?code=xxx  →  set remembered code and continue
// GET /?browse=folder  →  browse folder
// GET /?job=path  →  build history
func handleIndex(client *jenkins.Client, database *appdb.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := csrfToken(w, r)
		if r.Method == http.MethodPost {
			if rejectIfInvalidMutation(w, r) {
				return
			}
			if r.FormValue("action") == "logout" {
				clearAccessCodeCookie(w, r)
				_ = database.AddAuditLog("user", accessCodeFromRequest(r), "logout", "session", "/", nil)
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
			code := strings.TrimSpace(r.FormValue("code"))
			if code == "" {
				renderTemplate(w, "access.html", map[string]any{"Error": "Kode akses wajib diisi.", "CSRFToken": token})
				return
			}
			allowed, err := database.ValidateCode(code)
			if err != nil || len(allowed) == 0 {
				clearAccessCodeCookie(w, r)
				renderTemplate(w, "access.html", map[string]any{"Error": "Kode akses tidak valid.", "CSRFToken": token})
				return
			}
			setAccessCodeCookie(w, r, code)
			_ = database.AddAuditLog("user", code, "login", "session", "/", nil)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		code := accessCodeFromRequest(r)
		if code == "" {
			renderTemplate(w, "access.html", map[string]any{"CSRFToken": token})
			return
		}

		allowed, err := database.ValidateCode(code)
		if err != nil {
			clearAccessCodeCookie(w, r)
			renderTemplate(w, "access.html", map[string]any{"Error": "Kode akses tidak valid.", "CSRFToken": token})
			return
		}
		hooks, err := database.GetHooksByCode(code)
		if err != nil {
			slog.Error("fetch hooks failed", "code", code, "error", err)
		}
		hookLogs, err := database.GetRecentHookDeliveryLogsByCode(code, 10)
		if err != nil {
			slog.Error("fetch hook logs failed", "code", code, "error", err)
		}

		if strings.TrimSpace(r.URL.Query().Get("code")) != "" {
			setAccessCodeCookie(w, r, code)
			clean := cloneQueryWithout(r.URL.Query(), "code")
			target := "/"
			if encoded := clean.Encode(); encoded != "" {
				target += "?" + encoded
			}
			http.Redirect(w, r, target, http.StatusSeeOther)
			return
		}

		// Build history for a specific job
		if jobName := r.URL.Query().Get("job"); jobName != "" {
			if !isPathAllowed(jobName, allowed) {
				http.Error(w, "akses ditolak", http.StatusForbidden)
				return
			}
			limit := viper.GetInt("BUILD_LIMIT")
			builds, err := client.GetBuilds(jobName, limit)
			if err != nil {
				slog.Error("fetch builds failed", "job", jobName, "error", err)
			}
			renderPage(w, r, "index.html", "index.content", map[string]any{
				"JobName":    jobName,
				"Builds":     builds,
				"Hooks":      hooks,
				"HookLogs":   hookLogs,
				"CSRFToken":  token,
				"Error":      errStr(err),
				"Breadcrumb": breadcrumb(jobName),
			})
			return
		}

		// Browse folder or root
		folderPath := r.URL.Query().Get("browse")
		if folderPath != "" && !isPathAllowed(folderPath, allowed) {
			http.Error(w, "akses ditolak", http.StatusForbidden)
			return
		}

		jobs, err := client.GetJobsInFolder(folderPath)
		if err != nil {
			slog.Error("fetch jobs failed", "path", folderPath, "error", err)
		}
		filtered := filterJobs(jobs, folderPath, allowed)
		running, runErr := collectRunningJobsRecursive(client, folderPath, allowed)
		if runErr != nil {
			slog.Warn("fetch recursive running jobs failed", "path", folderPath, "error", runErr)
		}

		renderPage(w, r, "jobs.html", "jobs.content", map[string]any{
			"Jobs":        filtered,
			"RunningJobs": running,
			"FolderPath":  folderPath,
			"Hooks":       hooks,
			"HookLogs":    hookLogs,
			"CSRFToken":   token,
			"Breadcrumb":  breadcrumb(folderPath),
			"Error":       errStr(err),
		})
	}
}

func handleUserHooks(client *jenkins.Client, database *appdb.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := accessCodeFromRequest(r)
		if code == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if rejectIfInvalidMutation(w, r) {
			return
		}
		hookType := strings.TrimSpace(r.FormValue("type"))
		if hookType != "telegram" && hookType != "webhook" {
			http.Error(w, "invalid hook type", http.StatusBadRequest)
			return
		}

		var hookValue string
		if hookType == "telegram" {
			botToken := strings.TrimSpace(r.FormValue("bot_token"))
			chatID := strings.TrimSpace(r.FormValue("chat_id"))
			if botToken == "" || chatID == "" {
				http.Error(w, "telegram bot token and chat id are required", http.StatusBadRequest)
				return
			}
			payload, err := json.Marshal(map[string]string{
				"bot_token": botToken,
				"chat_id":   chatID,
			})
			if err != nil {
				http.Error(w, "invalid telegram payload", http.StatusInternalServerError)
				return
			}
			hookValue = string(payload)
		} else {
			hookValue = strings.TrimSpace(r.FormValue("value"))
			if hookValue == "" {
				http.Error(w, "webhook value required", http.StatusBadRequest)
				return
			}
			if err := validateWebhookTarget(hookValue); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		hook, err := database.AddHookByCode(code, hookType, hookValue)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := seedHookDeliveryState(client, database, code, *hook); err != nil {
			slog.Warn("seed hook delivery state failed", "hook_id", hook.ID, "code", code, "error", err)
		}
		_ = database.AddAuditLog("user", code, "add_hook", hookType, strconv.Itoa(hook.ID), map[string]string{"hook_type": hook.Type})
		renderTemplate(w, "user_hook_row", hook)
	}
}

func seedHookDeliveryState(client *jenkins.Client, database *appdb.DB, code string, hook appdb.Hook) error {
	allowed, err := database.ValidateCode(code)
	if err != nil {
		return err
	}
	worker := &webhookNotifier{
		client:   client,
		database: database,
	}
	jobPaths, err := worker.expandAllowedJobPaths(allowed)
	if err != nil {
		slog.Warn("seed hook delivery state expand failed", "code", code, "error", err)
	}
	for _, jobPath := range jobPaths {
		builds, buildErr := client.GetBuilds(jobPath, 1)
		if buildErr != nil || len(builds) == 0 {
			continue
		}
		build := builds[0]
		if build.Building {
			continue
		}
		state := build.Result
		if state == "" {
			continue
		}
		if err := database.UpsertHookDeliveryState(hook.ID, jobPath, build.Number, state); err != nil {
			slog.Warn("seed hook delivery state write failed", "hook_id", hook.ID, "job", jobPath, "error", err)
		}
	}
	return nil
}

func handleUserHookDelete(database *appdb.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := accessCodeFromRequest(r)
		if code == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/test") {
			if rejectIfInvalidMutation(w, r) {
				return
			}
			idStr := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/hooks/"), "/test")
			id, err := strconv.Atoi(idStr)
			if err != nil {
				http.Error(w, "bad id", http.StatusBadRequest)
				return
			}
			hook, err := database.GetHookByCodeAndID(code, id)
			if err != nil {
				http.Error(w, "hook not found", http.StatusNotFound)
				return
			}
			tester := &webhookNotifier{
				database: database,
				httpClient: &http.Client{
					Timeout: 10 * time.Second,
				},
			}
			payload := map[string]any{
				"event":      "test",
				"message":    "Manual hook test from Jenkins Build History",
				"hook_type":  hook.Type,
				"code_label": code,
				"timestamp":  time.Now().Format(time.RFC3339),
			}
			switch hook.Type {
			case "webhook":
				err = tester.sendWebhook(hook.Value, payload)
			case "telegram":
				err = tester.sendTelegramTest(*hook, code)
			default:
				err = fmt.Errorf("unsupported hook type")
			}
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = database.AddHookDeliveryLog(hook.ID, hook.Type, "manual/test", "test", "failed", err.Error())
				renderTemplate(w, "user_hook_test_result", map[string]any{
					"ID":      id,
					"Success": false,
					"Message": err.Error(),
				})
				return
			}
			_ = database.AddHookDeliveryLog(hook.ID, hook.Type, "manual/test", "test", "sent", "Test notification sent.")
			_ = database.AddAuditLog("user", code, "test_hook", hook.Type, strconv.Itoa(hook.ID), map[string]string{"hook_type": hook.Type})
			renderTemplate(w, "user_hook_test_result", map[string]any{
				"ID":      id,
				"Success": true,
				"Message": "Test notification sent.",
			})
			return
		}
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if rejectIfInvalidMutation(w, r) {
			return
		}
		idStr := strings.TrimPrefix(r.URL.Path, "/hooks/")
		id, err := strconv.Atoi(idStr)
		if err != nil {
			http.Error(w, "bad id", http.StatusBadRequest)
			return
		}
		if err := database.DeleteHookByCode(code, id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = database.AddAuditLog("user", code, "delete_hook", "hook", strconv.Itoa(id), nil)
		w.WriteHeader(http.StatusOK)
	}
}

func handleUserHookLogs(database *appdb.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := accessCodeFromRequest(r)
		if code == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		logs, err := database.GetRecentHookDeliveryLogsByCode(code, 10)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		renderTemplate(w, "user_hook_logs", map[string]any{"HookLogs": logs})
	}
}

func handleUserHookLogsStream(database *appdb.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := accessCodeFromRequest(r)
		if code == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}
		ctx := r.Context()

		sendLogs := func() error {
			logs, err := database.GetRecentHookDeliveryLogsByCode(code, 10)
			if err != nil {
				return err
			}
			html, err := renderTemplateToString("user_hook_logs", map[string]any{"HookLogs": logs})
			if err != nil {
				return err
			}
			payload, _ := json.Marshal(map[string]string{"html": html})
			fmt.Fprintf(w, "event: logs\ndata: %s\n\n", payload)
			flusher.Flush()
			return nil
		}

		if err := sendLogs(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		heartbeat := time.NewTicker(15 * time.Second)
		defer heartbeat.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := sendLogs(); err != nil {
					slog.Error("SSE hook logs stream failed", "code", code, "error", err)
					fmt.Fprintf(w, "event: error\ndata: %q\n\n", err.Error())
					flusher.Flush()
					return
				}
			case <-heartbeat.C:
				fmt.Fprintf(w, ": keep-alive\n\n")
				flusher.Flush()
			}
		}
	}
}

func allowedPathsFromRequest(database *appdb.DB, r *http.Request) ([]appdb.CodePath, bool) {
	code := accessCodeFromRequest(r)
	if code == "" {
		return nil, false
	}
	allowed, err := database.ValidateCode(code)
	if err != nil {
		return nil, false
	}
	return allowed, true
}

// GET /log/{jobName}/{buildNumber}
func handleLog(client *jenkins.Client, database *appdb.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		allowed, ok := allowedPathsFromRequest(database, r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		jobName, buildNum, ok := parseLogPath(r.URL.Path, "/log/")
		if !ok {
			http.Error(w, "bad path", 400)
			return
		}
		if !isPathAllowed(jobName, allowed) {
			http.Error(w, "akses ditolak", http.StatusForbidden)
			return
		}
		limit := viper.GetInt("BUILD_LIMIT")
		builds, _ := client.GetBuilds(jobName, limit)
		var target jenkins.Build
		for _, b := range builds {
			if b.Number == buildNum {
				target = b
				break
			}
		}
		stages, _, err := client.GetStages(jobName, buildNum)
		if err != nil {
			slog.Error("fetch stages failed", "job", jobName, "build", buildNum, "error", err)
		}
		renderTemplate(w, "log", map[string]any{
			"JobName":      jobName,
			"BuildNumber":  buildNum,
			"Building":     target.Building,
			"Result":       target.Result,
			"StatusClass":  target.StatusClass(),
			"CommitID":     target.CommitID,
			"ShortCommit":  target.ShortCommit(),
			"CommitMsg":    target.CommitMsg,
			"CommitAuthor": target.CommitAuthor,
			"BranchName":   target.BranchName,
			"Stages":       stages,
			"StageCount":   len(stages),
		})
	}
}

// GET /log-stream/{jobName}/{buildNumber} — SSE stage updates
func handleLogStream(client *jenkins.Client, database *appdb.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		allowed, ok := allowedPathsFromRequest(database, r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		jobName, buildNum, ok := parseLogPath(r.URL.Path, "/log-stream/")
		if !ok {
			http.Error(w, "bad path", 400)
			return
		}
		if !isPathAllowed(jobName, allowed) {
			http.Error(w, "akses ditolak", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", 500)
			return
		}
		ctx := r.Context()

		err := client.StreamStagesSSE(jobName, buildNum, func(stages []jenkins.Stage, status string, done bool) {
			select {
			case <-ctx.Done():
				return
			default:
			}
			payload, _ := json.Marshal(map[string]any{"stages": stages, "status": status, "done": done})
			event := "update"
			if done {
				event = "done"
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, payload)
			flusher.Flush()
		})
		if err != nil {
			slog.Error("SSE stream error", "error", err)
			fmt.Fprintf(w, "event: error\ndata: %s\n\n", err.Error())
			flusher.Flush()
		}
	}
}

// GET /job-stream/{jobName} — SSE build timeline updates
func handleJobStream(client *jenkins.Client, database *appdb.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		allowed, ok := allowedPathsFromRequest(database, r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		jobName := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/job-stream/"))
		if jobName == "" {
			http.Error(w, "bad path", http.StatusBadRequest)
			return
		}
		jobName, err := url.PathUnescape(jobName)
		if err != nil || jobName == "" {
			http.Error(w, "bad path", http.StatusBadRequest)
			return
		}
		if !isPathAllowed(jobName, allowed) {
			http.Error(w, "akses ditolak", http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}

		ctx := r.Context()
		limit := viper.GetInt("BUILD_LIMIT")
		sendTimeline := func() error {
			builds, err := client.GetBuilds(jobName, limit)
			if err != nil {
				return err
			}
			html, err := renderTemplateToString("build_timeline_section", map[string]any{
				"JobName": jobName,
				"Builds":  builds,
			})
			if err != nil {
				return err
			}
			payload, _ := json.Marshal(map[string]string{"html": html})
			fmt.Fprintf(w, "event: timeline\ndata: %s\n\n", payload)
			flusher.Flush()
			return nil
		}

		if err := sendTimeline(); err != nil {
			slog.Error("SSE job stream initial send failed", "job", jobName, "error", err)
			fmt.Fprintf(w, "event: error\ndata: %q\n\n", err.Error())
			flusher.Flush()
			return
		}

		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := sendTimeline(); err != nil {
					slog.Error("SSE job stream update failed", "job", jobName, "error", err)
					fmt.Fprintf(w, "event: error\ndata: %q\n\n", err.Error())
					flusher.Flush()
					return
				}
			}
		}
	}
}

// GET /running-stream?browse=folder — SSE running builds updates for current folder scope
func handleRunningStream(client *jenkins.Client, database *appdb.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		allowed, ok := allowedPathsFromRequest(database, r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		folderPath := strings.TrimSpace(r.URL.Query().Get("browse"))
		if folderPath != "" && !isPathAllowed(folderPath, allowed) {
			http.Error(w, "akses ditolak", http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}

		ctx := r.Context()
		sendRunning := func() error {
			running, err := collectRunningJobsRecursive(client, folderPath, allowed)
			if err != nil {
				return err
			}
			html, err := renderTemplateToString("running_jobs_section", map[string]any{
				"FolderPath":  folderPath,
				"RunningJobs": running,
			})
			if err != nil {
				return err
			}
			payload, _ := json.Marshal(map[string]string{"html": html})
			fmt.Fprintf(w, "event: running\ndata: %s\n\n", payload)
			flusher.Flush()
			return nil
		}

		if err := sendRunning(); err != nil {
			slog.Error("SSE running stream initial send failed", "path", folderPath, "error", err)
			fmt.Fprintf(w, "event: error\ndata: %q\n\n", err.Error())
			flusher.Flush()
			return
		}

		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := sendRunning(); err != nil {
					slog.Error("SSE running stream update failed", "path", folderPath, "error", err)
					fmt.Fprintf(w, "event: error\ndata: %q\n\n", err.Error())
					flusher.Flush()
					return
				}
			}
		}
	}
}

// ── Admin handlers ────────────────────────────────────────────────────────

// GET /admin — panel or login form
func handleAdmin(client *jenkins.Client, database *appdb.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !validSession(r) {
			renderTemplate(w, "admin_login.html", map[string]any{"CSRFToken": csrfToken(w, r)})
			return
		}
		codes, err := database.GetAllCodes()
		renderTemplate(w, "admin.html", map[string]any{
			"Codes":     codes,
			"Error":     errStr(err),
			"CSRFToken": csrfToken(w, r),
		})
	}
}

func handleAdminAudit(database *appdb.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !validSession(r) {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}
		logs, err := database.GetAuditLogs(200)
		renderTemplate(w, "admin_audit.html", map[string]any{
			"Logs":      logs,
			"Error":     errStr(err),
			"CSRFToken": csrfToken(w, r),
		})
	}
}

// POST /admin/login
func handleAdminLogin(database *appdb.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}
		if rejectIfInvalidMutation(w, r) {
			return
		}
		if r.FormValue("password") == viper.GetString("ADMIN_PASSWORD") {
			token, err := newSession()
			if err != nil {
				slog.Error("session creation failed", "error", err)
				http.Error(w, "session error", http.StatusInternalServerError)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name:     "admin_token",
				Value:    token,
				Path:     "/",
				HttpOnly: true,
				MaxAge:   43200, // 12h
				SameSite: http.SameSiteLaxMode,
				Secure:   r.TLS != nil,
			})
			_ = database.AddAuditLog("admin", "admin", "login", "session", "/admin", nil)
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
		} else {
			_ = database.AddAuditLog("admin", "admin", "login_failed", "session", "/admin", nil)
			renderTemplate(w, "admin_login.html", map[string]any{"Error": "Password salah.", "CSRFToken": csrfToken(w, r)})
		}
	}
}

// POST /admin/logout
func handleAdminLogout(database *appdb.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if rejectIfInvalidMutation(w, r) {
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "admin_token",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   r.TLS != nil,
		})
		_ = database.AddAuditLog("admin", "admin", "logout", "session", "/admin", nil)
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
	}
}

// POST /admin/codes — create new code (HTMX)
func handleAdminCodes(database *appdb.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !validSession(r) {
			http.Error(w, "unauthorized", 401)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		if rejectIfInvalidMutation(w, r) {
			return
		}
		label := strings.TrimSpace(r.FormValue("label"))
		code := strings.TrimSpace(r.FormValue("code"))
		if label == "" || code == "" {
			http.Error(w, "label and code required", 400)
			return
		}
		ac, err := database.CreateCode(code, label)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		_ = database.AddAuditLog("admin", "admin", "create_access_code", "access_code", strconv.Itoa(ac.ID), map[string]string{"label": label})
		renderTemplate(w, "admin_code_row", ac)
	}
}

// /admin/codes/{id}         DELETE → delete code
// /admin/codes/{id}/paths   POST   → add path
func handleAdminCodesSub(database *appdb.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !validSession(r) {
			http.Error(w, "unauthorized", 401)
			return
		}
		// strip /admin/codes/
		rest := strings.TrimPrefix(r.URL.Path, "/admin/codes/")
		parts := strings.SplitN(rest, "/", 2)
		codeID, err := strconv.Atoi(parts[0])
		if err != nil {
			http.Error(w, "bad id", 400)
			return
		}

		// DELETE /admin/codes/{id}
		if len(parts) == 1 && r.Method == http.MethodDelete {
			if rejectIfInvalidMutation(w, r) {
				return
			}
			if err := database.DeleteCode(codeID); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			_ = database.AddAuditLog("admin", "admin", "delete_access_code", "access_code", strconv.Itoa(codeID), nil)
			w.WriteHeader(http.StatusOK) // HTMX swap:outerHTML with empty body removes the element
			return
		}

		// POST /admin/codes/{id}/paths
		if len(parts) == 2 && parts[1] == "paths" && r.Method == http.MethodPost {
			if rejectIfInvalidMutation(w, r) {
				return
			}
			path := strings.TrimSpace(r.FormValue("path"))
			if path == "" {
				http.Error(w, "path required", 400)
				return
			}
			cp, err := database.AddPath(codeID, path)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			_ = database.AddAuditLog("admin", "admin", "add_path", "path", strconv.Itoa(cp.ID), map[string]string{"path": path})
			renderTemplate(w, "admin_path_row", cp)
			return
		}

		http.Error(w, "not found", 404)
	}
}

// DELETE /admin/paths/{id}
func handleAdminPaths(database *appdb.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !validSession(r) {
			http.Error(w, "unauthorized", 401)
			return
		}
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", 405)
			return
		}
		if rejectIfInvalidMutation(w, r) {
			return
		}
		idStr := strings.TrimPrefix(r.URL.Path, "/admin/paths/")
		id, err := strconv.Atoi(idStr)
		if err != nil {
			http.Error(w, "bad id", 400)
			return
		}
		if err := database.DeletePath(id); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		_ = database.AddAuditLog("admin", "admin", "delete_path", "path", strconv.Itoa(id), nil)
		w.WriteHeader(http.StatusOK)
	}
}

type adminPickerOption struct {
	Path     string
	Label    string
	IsFolder bool
}

type adminPickerView struct {
	CodeID     int
	BrowsePath string
	ParentPath string
	Items      []adminPickerOption
	Error      string
}

func handleAdminPicker(client *jenkins.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !validSession(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		codeID, err := strconv.Atoi(r.URL.Query().Get("code_id"))
		if err != nil || codeID <= 0 {
			http.Error(w, "bad code id", http.StatusBadRequest)
			return
		}
		renderTemplate(w, "admin_path_picker", adminPickerData(client, codeID, r.URL.Query().Get("browse")))
	}
}

func adminPickerData(client *jenkins.Client, codeID int, browsePath string) adminPickerView {
	view := adminPickerView{
		CodeID:     codeID,
		BrowsePath: browsePath,
		ParentPath: parentPath(browsePath),
	}

	jobs, err := client.GetJobsInFolder(browsePath)
	if err != nil {
		view.Error = errStr(err)
		return view
	}

	for _, job := range jobs {
		fullPath := job.Name
		if browsePath != "" {
			fullPath = browsePath + "/" + job.Name
		}
		view.Items = append(view.Items, adminPickerOption{
			Path:     fullPath,
			Label:    job.Name,
			IsFolder: job.IsFolder(),
		})
	}
	return view
}

// ── Helpers ───────────────────────────────────────────────────────────────

func breadcrumb(path string) []map[string]string {
	if path == "" {
		return nil
	}
	parts := strings.Split(path, "/")
	crumbs := make([]map[string]string, len(parts))
	for i, p := range parts {
		crumbs[i] = map[string]string{
			"Name": p,
			"Path": strings.Join(parts[:i+1], "/"),
		}
	}
	return crumbs
}

func parseLogPath(urlPath, prefix string) (jobName string, buildNum int, ok bool) {
	trimmed := strings.TrimPrefix(urlPath, prefix)
	idx := strings.LastIndex(trimmed, "/")
	if idx < 0 {
		return "", 0, false
	}
	n, err := strconv.Atoi(trimmed[idx+1:])
	if err != nil || trimmed[:idx] == "" {
		return "", 0, false
	}
	return trimmed[:idx], n, true
}

func renderTemplate(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, name, withTemplateDefaults(data)); err != nil {
		slog.Error("template error", "name", name, "error", err)
		http.Error(w, fmt.Sprintf("template error: %v", err), 500)
	}
}

func renderTemplateToString(name string, data any) (string, error) {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, name, withTemplateDefaults(data)); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func renderPage(w http.ResponseWriter, r *http.Request, fullName, partialName string, data any) {
	if r.Header.Get("HX-Request") == "true" {
		renderTemplate(w, partialName, data)
		return
	}
	renderTemplate(w, fullName, data)
}

func errStr(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

func parentPath(path string) string {
	if path == "" {
		return ""
	}
	idx := strings.LastIndex(path, "/")
	if idx < 0 {
		return ""
	}
	return path[:idx]
}

func cloneQueryWithout(src url.Values, keys ...string) url.Values {
	out := make(url.Values, len(src))
	for key, values := range src {
		skip := false
		for _, blocked := range keys {
			if key == blocked {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		copied := make([]string, len(values))
		copy(copied, values)
		out[key] = copied
	}
	return out
}
