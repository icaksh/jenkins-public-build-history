package db

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var sqliteTimeLayouts = []string{
	"2006-01-02 15:04:05.999999999-07:00",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05-07:00",
	"2006-01-02 15:04:05",
	time.RFC3339Nano,
	time.RFC3339,
}

type DB struct {
	*sql.DB
	hookCipher *hookCipher
}

type hookCipher struct {
	aead cipher.AEAD
}

type AccessCode struct {
	ID        int
	Code      string
	Label     string
	CreatedAt time.Time
	Paths     []CodePath
	Hooks     []Hook
}

type CodePath struct {
	ID   int
	Path string
}

type Hook struct {
	ID    int
	Type  string
	Value string
	Meta  map[string]string
}

type AuditLog struct {
	ID          int
	ActorType   string
	ActorLabel  string
	Action      string
	TargetType  string
	TargetValue string
	Details     map[string]string
	CreatedAt   time.Time
}

type HookDeliveryLog struct {
	ID        int
	HookID    int
	HookType  string
	JobPath   string
	Event     string
	Status    string
	Message   string
	CreatedAt time.Time
}

type telegramHookValue struct {
	BotToken string `json:"bot_token"`
	ChatID   string `json:"chat_id"`
}

func New(path, hookSecret string) (*DB, error) {
	sqlDB, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(1)
	db := &DB{DB: sqlDB}
	if hookSecret != "" {
		db.hookCipher, err = newHookCipher(hookSecret)
		if err != nil {
			return nil, err
		}
	}
	if err := db.migrate(); err != nil {
		return nil, err
	}
	return db, db.migrateHookValues()
}

func newHookCipher(secret string) (*hookCipher, error) {
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &hookCipher{aead: aead}, nil
}

func (d *DB) migrate() error {
	_, err := d.Exec(`
		CREATE TABLE IF NOT EXISTS access_codes (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			code       TEXT    UNIQUE NOT NULL,
			label      TEXT    NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS code_paths (
			id      INTEGER PRIMARY KEY AUTOINCREMENT,
			code_id INTEGER NOT NULL REFERENCES access_codes(id) ON DELETE CASCADE,
			path    TEXT    NOT NULL,
			UNIQUE(code_id, path)
		);
		CREATE TABLE IF NOT EXISTS telegram_hooks (
			id      INTEGER PRIMARY KEY AUTOINCREMENT,
			code_id INTEGER NOT NULL REFERENCES access_codes(id) ON DELETE CASCADE,
			token   TEXT    NOT NULL,
			UNIQUE(code_id, token)
		);
		CREATE TABLE IF NOT EXISTS hooks (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			code_id    INTEGER NOT NULL REFERENCES access_codes(id) ON DELETE CASCADE,
			hook_type  TEXT    NOT NULL,
			hook_value TEXT    NOT NULL,
			UNIQUE(code_id, hook_type, hook_value)
		);
		INSERT OR IGNORE INTO hooks (code_id, hook_type, hook_value)
		SELECT code_id, 'telegram', token FROM telegram_hooks;
		CREATE TABLE IF NOT EXISTS hook_delivery_state (
			hook_id            INTEGER NOT NULL REFERENCES hooks(id) ON DELETE CASCADE,
			job_path           TEXT    NOT NULL,
			last_build_number  INTEGER NOT NULL,
			last_result        TEXT    NOT NULL,
			notified_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (hook_id, job_path)
		);
		CREATE TABLE IF NOT EXISTS telegram_live_state (
			hook_id            INTEGER NOT NULL REFERENCES hooks(id) ON DELETE CASCADE,
			job_path           TEXT    NOT NULL,
			build_number       INTEGER NOT NULL,
			message_id         INTEGER NOT NULL,
			last_stage_hash    TEXT    NOT NULL,
			last_build_status  TEXT    NOT NULL,
			updated_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (hook_id, job_path)
		);
		CREATE TABLE IF NOT EXISTS hook_delivery_logs (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			hook_id    INTEGER NOT NULL REFERENCES hooks(id) ON DELETE CASCADE,
			hook_type  TEXT    NOT NULL,
			job_path   TEXT    NOT NULL,
			event      TEXT    NOT NULL,
			status     TEXT    NOT NULL,
			message    TEXT    NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS audit_logs (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			actor_type   TEXT    NOT NULL,
			actor_label  TEXT    NOT NULL,
			action       TEXT    NOT NULL,
			target_type  TEXT    NOT NULL,
			target_value TEXT    NOT NULL,
			details      TEXT    NOT NULL DEFAULT '{}',
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	return err
}

func (d *DB) migrateHookValues() error {
	rows, err := d.Query(`SELECT id, hook_value FROM hooks`)
	if err != nil {
		return err
	}
	defer rows.Close()

	type pending struct {
		id    int
		value string
	}
	var updates []pending
	for rows.Next() {
		var item pending
		if err := rows.Scan(&item.id, &item.value); err != nil {
			return err
		}
		if strings.HasPrefix(item.value, "enc:v1:") {
			continue
		}
		updates = append(updates, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, item := range updates {
		enc, err := d.encryptHookValue(item.value)
		if err != nil {
			return err
		}
		if _, err := d.Exec(`UPDATE hooks SET hook_value = ? WHERE id = ?`, enc, item.id); err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) encryptHookValue(value string) (string, error) {
	if d.hookCipher == nil {
		return value, nil
	}
	nonce := make([]byte, d.hookCipher.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := d.hookCipher.aead.Seal(nil, nonce, []byte(value), nil)
	blob := append(nonce, ciphertext...)
	return "enc:v1:" + base64.RawStdEncoding.EncodeToString(blob), nil
}

func (d *DB) decryptHookValue(value string) (string, error) {
	if !strings.HasPrefix(value, "enc:v1:") || d.hookCipher == nil {
		return value, nil
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, "enc:v1:"))
	if err != nil {
		return "", err
	}
	nonceSize := d.hookCipher.aead.NonceSize()
	if len(raw) < nonceSize {
		return "", fmt.Errorf("invalid encrypted hook")
	}
	plaintext, err := d.hookCipher.aead.Open(nil, raw[:nonceSize], raw[nonceSize:], nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func (d *DB) GetAllCodes() ([]AccessCode, error) {
	rows, err := d.Query(`
		SELECT ac.id, ac.code, ac.label, ac.created_at,
		       cp.id, cp.path,
		       h.id, h.hook_type, h.hook_value
		FROM access_codes ac
		LEFT JOIN code_paths cp ON cp.code_id = ac.id
		LEFT JOIN hooks h ON h.code_id = ac.id
		ORDER BY ac.created_at DESC, cp.id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	codesMap := make(map[int]*AccessCode)
	var order []int

	for rows.Next() {
		var (
			acID      int
			code, lbl string
			createdAt string
			pathID    sql.NullInt64
			pathStr   sql.NullString
			hookID    sql.NullInt64
			hookType  sql.NullString
			hookValue sql.NullString
		)
		if err := rows.Scan(&acID, &code, &lbl, &createdAt, &pathID, &pathStr, &hookID, &hookType, &hookValue); err != nil {
			return nil, err
		}
		if _, ok := codesMap[acID]; !ok {
			t := parseSQLiteTime(createdAt)
			codesMap[acID] = &AccessCode{ID: acID, Code: code, Label: lbl, CreatedAt: t}
			order = append(order, acID)
		}
		if pathID.Valid {
			exists := false
			for _, path := range codesMap[acID].Paths {
				if path.ID == int(pathID.Int64) {
					exists = true
					break
				}
			}
			if !exists {
				codesMap[acID].Paths = append(codesMap[acID].Paths, CodePath{
					ID: int(pathID.Int64), Path: pathStr.String,
				})
			}
		}
		if hookID.Valid {
			exists := false
			for _, hook := range codesMap[acID].Hooks {
				if hook.ID == int(hookID.Int64) {
					exists = true
					break
				}
			}
			if !exists {
				decoded, err := d.decryptHookValue(hookValue.String)
				if err != nil {
					return nil, err
				}
				codesMap[acID].Hooks = append(codesMap[acID].Hooks, normalizeHook(Hook{
					ID:    int(hookID.Int64),
					Type:  hookType.String,
					Value: decoded,
				}))
			}
		}
	}
	result := make([]AccessCode, 0, len(order))
	for _, id := range order {
		result = append(result, *codesMap[id])
	}
	return result, rows.Err()
}

func (d *DB) CreateCode(code, label string) (*AccessCode, error) {
	res, err := d.Exec(`INSERT INTO access_codes (code, label) VALUES (?, ?)`, code, label)
	if err != nil {
		return nil, fmt.Errorf("code already exists or invalid: %w", err)
	}
	id, _ := res.LastInsertId()
	return &AccessCode{ID: int(id), Code: code, Label: label, CreatedAt: time.Now()}, nil
}

func (d *DB) DeleteCode(id int) error {
	_, err := d.Exec(`DELETE FROM access_codes WHERE id = ?`, id)
	return err
}

func (d *DB) AddPath(codeID int, path string) (*CodePath, error) {
	res, err := d.Exec(`INSERT OR IGNORE INTO code_paths (code_id, path) VALUES (?, ?)`, codeID, path)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &CodePath{ID: int(id), Path: path}, nil
}

func (d *DB) DeletePath(id int) error {
	_, err := d.Exec(`DELETE FROM code_paths WHERE id = ?`, id)
	return err
}

func (d *DB) AddHook(codeID int, hookType, hookValue string) (*Hook, error) {
	existing, err := d.GetHooksForCodeID(codeID)
	if err != nil {
		return nil, err
	}
	for _, hook := range existing {
		if hook.Type == hookType && hook.Value == hookValue {
			return &hook, nil
		}
	}

	encryptedValue, err := d.encryptHookValue(hookValue)
	if err != nil {
		return nil, err
	}
	res, err := d.Exec(`INSERT INTO hooks (code_id, hook_type, hook_value) VALUES (?, ?, ?)`, codeID, hookType, encryptedValue)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	hook := normalizeHook(Hook{ID: int(id), Type: hookType, Value: hookValue})
	return &hook, nil
}

func (d *DB) DeleteHook(id int) error {
	_, err := d.Exec(`DELETE FROM hooks WHERE id = ?`, id)
	return err
}

func (d *DB) GetHooksByCode(code string) ([]Hook, error) {
	var codeID int
	if err := d.QueryRow(`SELECT id FROM access_codes WHERE code = ?`, code).Scan(&codeID); err != nil {
		return nil, err
	}
	return d.GetHooksForCodeID(codeID)
}

func (d *DB) GetHooksForCodeID(codeID int) ([]Hook, error) {
	rows, err := d.Query(`
		SELECT h.id, h.hook_type, h.hook_value
		FROM hooks h
		WHERE h.code_id = ?
		ORDER BY h.id
	`, codeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hooks []Hook
	for rows.Next() {
		var hook Hook
		if err := rows.Scan(&hook.ID, &hook.Type, &hook.Value); err != nil {
			return nil, err
		}
		hook.Value, err = d.decryptHookValue(hook.Value)
		if err != nil {
			return nil, err
		}
		hooks = append(hooks, normalizeHook(hook))
	}
	return hooks, rows.Err()
}

func (d *DB) AddHookByCode(code, hookType, hookValue string) (*Hook, error) {
	var codeID int
	if err := d.QueryRow(`SELECT id FROM access_codes WHERE code = ?`, code).Scan(&codeID); err != nil {
		return nil, err
	}
	return d.AddHook(codeID, hookType, hookValue)
}

func (d *DB) DeleteHookByCode(code string, id int) error {
	res, err := d.Exec(`
		DELETE FROM hooks
		WHERE id = ?
		  AND code_id = (SELECT id FROM access_codes WHERE code = ?)
	`, id, code)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("hook not found")
	}
	return nil
}

func (d *DB) GetHookByCodeAndID(code string, id int) (*Hook, error) {
	row := d.QueryRow(`
		SELECT h.id, h.hook_type, h.hook_value
		FROM hooks h
		WHERE h.id = ?
		  AND h.code_id = (SELECT id FROM access_codes WHERE code = ?)
	`, id, code)

	var hook Hook
	if err := row.Scan(&hook.ID, &hook.Type, &hook.Value); err != nil {
		return nil, err
	}
	value, err := d.decryptHookValue(hook.Value)
	if err != nil {
		return nil, err
	}
	hook.Value = value
	normalized := normalizeHook(hook)
	return &normalized, nil
}

func (d *DB) GetHookDeliveryState(hookID int, jobPath string) (int, string, bool, error) {
	var buildNumber int
	var result string
	err := d.QueryRow(`
		SELECT last_build_number, last_result
		FROM hook_delivery_state
		WHERE hook_id = ? AND job_path = ?
	`, hookID, jobPath).Scan(&buildNumber, &result)
	if err == sql.ErrNoRows {
		return 0, "", false, nil
	}
	if err != nil {
		return 0, "", false, err
	}
	return buildNumber, result, true, nil
}

func (d *DB) UpsertHookDeliveryState(hookID int, jobPath string, buildNumber int, result string) error {
	_, err := d.Exec(`
		INSERT INTO hook_delivery_state (hook_id, job_path, last_build_number, last_result, notified_at)
		VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(hook_id, job_path)
		DO UPDATE SET
			last_build_number = excluded.last_build_number,
			last_result = excluded.last_result,
			notified_at = CURRENT_TIMESTAMP
	`, hookID, jobPath, buildNumber, result)
	return err
}

func (d *DB) GetTelegramLiveState(hookID int, jobPath string) (int, int, string, string, bool, error) {
	var buildNumber, messageID int
	var stageHash, buildStatus string
	err := d.QueryRow(`
		SELECT build_number, message_id, last_stage_hash, last_build_status
		FROM telegram_live_state
		WHERE hook_id = ? AND job_path = ?
	`, hookID, jobPath).Scan(&buildNumber, &messageID, &stageHash, &buildStatus)
	if err == sql.ErrNoRows {
		return 0, 0, "", "", false, nil
	}
	if err != nil {
		return 0, 0, "", "", false, err
	}
	return buildNumber, messageID, stageHash, buildStatus, true, nil
}

func (d *DB) UpsertTelegramLiveState(hookID int, jobPath string, buildNumber, messageID int, stageHash, buildStatus string) error {
	_, err := d.Exec(`
		INSERT INTO telegram_live_state (hook_id, job_path, build_number, message_id, last_stage_hash, last_build_status, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(hook_id, job_path)
		DO UPDATE SET
			build_number = excluded.build_number,
			message_id = excluded.message_id,
			last_stage_hash = excluded.last_stage_hash,
			last_build_status = excluded.last_build_status,
			updated_at = CURRENT_TIMESTAMP
	`, hookID, jobPath, buildNumber, messageID, stageHash, buildStatus)
	return err
}

func (d *DB) DeleteTelegramLiveState(hookID int, jobPath string) error {
	_, err := d.Exec(`DELETE FROM telegram_live_state WHERE hook_id = ? AND job_path = ?`, hookID, jobPath)
	return err
}

func (d *DB) AddHookDeliveryLog(hookID int, hookType, jobPath, event, status, message string) error {
	_, err := d.Exec(`
		INSERT INTO hook_delivery_logs (hook_id, hook_type, job_path, event, status, message)
		VALUES (?, ?, ?, ?, ?, ?)
	`, hookID, hookType, jobPath, event, status, message)
	return err
}

func (d *DB) GetRecentHookDeliveryLogsByCode(code string, limit int) ([]HookDeliveryLog, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := d.Query(`
		SELECT l.id, l.hook_id, l.hook_type, l.job_path, l.event, l.status, l.message, l.created_at
		FROM hook_delivery_logs l
		JOIN hooks h ON h.id = l.hook_id
		JOIN access_codes ac ON ac.id = h.code_id
		WHERE ac.code = ?
		ORDER BY l.id DESC
		LIMIT ?
	`, code, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []HookDeliveryLog
	for rows.Next() {
		var item HookDeliveryLog
		var createdAt string
		if err := rows.Scan(&item.ID, &item.HookID, &item.HookType, &item.JobPath, &item.Event, &item.Status, &item.Message, &createdAt); err != nil {
			return nil, err
		}
		item.CreatedAt = parseSQLiteTime(createdAt)
		logs = append(logs, item)
	}
	return logs, rows.Err()
}

func (d *DB) AddAuditLog(actorType, actorLabel, action, targetType, targetValue string, details map[string]string) error {
	if details == nil {
		details = map[string]string{}
	}
	payload, err := json.Marshal(details)
	if err != nil {
		return err
	}
	_, err = d.Exec(`
		INSERT INTO audit_logs (actor_type, actor_label, action, target_type, target_value, details)
		VALUES (?, ?, ?, ?, ?, ?)
	`, actorType, actorLabel, action, targetType, targetValue, string(payload))
	return err
}

func (d *DB) GetAuditLogs(limit int) ([]AuditLog, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := d.Query(`
		SELECT id, actor_type, actor_label, action, target_type, target_value, details, created_at
		FROM audit_logs
		ORDER BY id DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []AuditLog
	for rows.Next() {
		var (
			logItem   AuditLog
			details   string
			createdAt string
		)
		if err := rows.Scan(
			&logItem.ID,
			&logItem.ActorType,
			&logItem.ActorLabel,
			&logItem.Action,
			&logItem.TargetType,
			&logItem.TargetValue,
			&details,
			&createdAt,
		); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(details), &logItem.Details); err != nil {
			logItem.Details = map[string]string{"raw": details}
		}
		logItem.CreatedAt = parseSQLiteTime(createdAt)
		logs = append(logs, logItem)
	}
	return logs, rows.Err()
}

func parseSQLiteTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	for _, layout := range sqliteTimeLayouts {
		if t, err := time.Parse(layout, value); err == nil {
			return t
		}
	}
	return time.Time{}
}

func normalizeHook(h Hook) Hook {
	if h.Type != "telegram" {
		return h
	}
	var tg telegramHookValue
	if err := json.Unmarshal([]byte(h.Value), &tg); err == nil && (tg.BotToken != "" || tg.ChatID != "") {
		h.Meta = map[string]string{
			"bot_token": tg.BotToken,
			"chat_id":   tg.ChatID,
		}
		return h
	}
	h.Meta = map[string]string{
		"bot_token": h.Value,
	}
	return h
}

func (h Hook) DisplayValue() string {
	if h.Type != "telegram" {
		return h.Value
	}
	botToken := h.Meta["bot_token"]
	chatID := h.Meta["chat_id"]
	if chatID == "" {
		return "Bot token: " + maskSecret(botToken)
	}
	return "Bot token: " + maskSecret(botToken) + " | Chat ID: " + maskSecret(chatID)
}

func maskSecret(value string) string {
	if value == "" {
		return ""
	}
	if len(value) <= 4 {
		return strings.Repeat("*", len(value))
	}
	if len(value) <= 8 {
		return value[:2] + strings.Repeat("*", len(value)-4) + value[len(value)-2:]
	}
	return value[:4] + "..." + value[len(value)-4:]
}

// ValidateCode returns the allowed paths for a given access code.
// Returns error if code not found or has no paths.
func (d *DB) ValidateCode(code string) ([]CodePath, error) {
	rows, err := d.Query(`
		SELECT cp.id, cp.path
		FROM access_codes ac
		JOIN code_paths cp ON cp.code_id = ac.id
		WHERE ac.code = ?
	`, code)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var paths []CodePath
	for rows.Next() {
		var cp CodePath
		if err := rows.Scan(&cp.ID, &cp.Path); err != nil {
			return nil, err
		}
		paths = append(paths, cp)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("invalid access code")
	}
	return paths, rows.Err()
}
