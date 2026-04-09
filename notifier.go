package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	neturl "net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	appdb "github.com/icaksh/jenkins-public-build-history/db"
	"github.com/icaksh/jenkins-public-build-history/jenkins"
	"github.com/spf13/viper"
)

type webhookNotifier struct {
	client         *jenkins.Client
	database       *appdb.DB
	httpClient     *http.Client
	interval       time.Duration
	activeInterval time.Duration
}

func startWebhookNotifier(client *jenkins.Client, database *appdb.DB) {
	interval, err := time.ParseDuration(viper.GetString("NOTIFY_POLL_INTERVAL"))
	if err != nil || interval <= 0 {
		slog.Warn("invalid NOTIFY_POLL_INTERVAL, using 10s", "value", viper.GetString("NOTIFY_POLL_INTERVAL"))
		interval = 10 * time.Second
	}
	activeInterval, err := time.ParseDuration(viper.GetString("NOTIFY_ACTIVE_POLL_INTERVAL"))
	if err != nil || activeInterval <= 0 {
		activeInterval = 2 * time.Second
	}
	if activeInterval > interval {
		activeInterval = interval
	}

	worker := &webhookNotifier{
		client:         client,
		database:       database,
		interval:       interval,
		activeInterval: activeInterval,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}

	go worker.loop()
}

func (n *webhookNotifier) loop() {
	for {
		active := n.safePoll()
		if active {
			time.Sleep(n.activeInterval)
			continue
		}
		time.Sleep(n.interval)
	}
}

func (n *webhookNotifier) safePoll() bool {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error("notifier: panic recovered", "panic", rec)
		}
	}()
	return n.poll()
}

func (n *webhookNotifier) poll() bool {
	startedAt := time.Now()
	codes, err := n.database.GetAllCodes()
	if err != nil {
		slog.Error("notifier: fetch access codes failed", "error", err)
		return false
	}
	active := false

	for _, code := range codes {
		jobPaths, err := n.expandAllowedJobPaths(code.Paths)
		if err != nil {
			slog.Warn("notifier: expand allowed paths failed", "code", code.Code, "error", err)
		}
		runningJobs, runErr := collectRunningJobsRecursive(n.client, "", code.Paths)
		if runErr != nil {
			slog.Warn("notifier: collect running jobs failed", "code", code.Code, "error", runErr)
		}
		pathSet := make(map[string]struct{}, len(jobPaths)+len(runningJobs))
		for _, jobPath := range jobPaths {
			pathSet[jobPath] = struct{}{}
		}
		for _, running := range runningJobs {
			pathSet[running.FullPath] = struct{}{}
		}
		combined := make([]string, 0, len(pathSet))
		for path := range pathSet {
			combined = append(combined, path)
		}
		sort.Strings(combined)
		for _, jobPath := range combined {
			if n.processJob(code, jobPath) {
				active = true
			}
		}
	}
	slog.Debug("notifier: poll completed", "codes", len(codes), "active", active, "duration", time.Since(startedAt).String())
	return active
}

func (n *webhookNotifier) expandAllowedJobPaths(paths []appdb.CodePath) ([]string, error) {
	seen := make(map[string]struct{})
	var firstErr error

	for _, path := range paths {
		if err := n.expandAllowedPath(path.Path, seen); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	out := make([]string, 0, len(seen))
	for path := range seen {
		out = append(out, path)
	}
	sort.Strings(out)
	return out, firstErr
}

func (n *webhookNotifier) expandAllowedPath(path string, seen map[string]struct{}) error {
	if path == "" {
		return nil
	}
	if _, ok := seen[path]; ok {
		return nil
	}

	if _, err := n.client.GetBuilds(path, 1); err == nil {
		seen[path] = struct{}{}
		return nil
	}

	jobs, err := n.client.GetJobsInFolder(path)
	if err != nil {
		return err
	}
	for _, job := range jobs {
		fullPath := job.Name
		if path != "" {
			fullPath = path + "/" + job.Name
		}
		if job.IsFolder() {
			if err := n.expandAllowedPath(fullPath, seen); err != nil {
				slog.Warn("notifier: skip folder during expansion", "path", fullPath, "error", err)
			}
			continue
		}
		seen[fullPath] = struct{}{}
	}
	return nil
}

func (n *webhookNotifier) processJob(code appdb.AccessCode, jobPath string) bool {
	builds, err := n.client.GetBuilds(jobPath, 1)
	if err != nil || len(builds) == 0 {
		if err != nil {
			slog.Warn("notifier: fetch latest build failed", "job", jobPath, "error", err)
		}
		return false
	}

	build := builds[0]
	if build.Building {
		stages, buildStatus, err := n.client.GetStages(jobPath, build.Number)
		visibleStages := visibleTelegramStages(stages)
		if err != nil {
			slog.Warn("notifier: fetch live stages failed", "job", jobPath, "build", build.Number, "error", err)
			buildStatus = "IN_PROGRESS"
		} else if isFinalResult(buildStatus) {
			build.Result = buildStatus
			build.Building = false
			if build.Duration <= 0 {
				if duration := sumStageDurations(visibleStages); duration > 0 {
					build.Duration = duration
				}
			}
		}
		if buildStatus == "IN_PROGRESS" || buildStatus == "PAUSED_PENDING_INPUT" {
			if freshBuild, err := n.client.GetBuild(jobPath, build.Number); err == nil {
				if !freshBuild.Building && isFinalResult(freshBuild.Result) {
					build = freshBuild
				}
			}
			if build.Building {
				if consoleResult, err := n.client.GetBuildConsoleResult(jobPath, build.Number); err == nil && isFinalResult(consoleResult) {
					build.Result = consoleResult
					build.Building = false
				}
			}
		}
		if build.Building {
			for _, hook := range code.Hooks {
				lastBuild, lastResult, exists, err := n.database.GetHookDeliveryState(hook.ID, jobPath)
				if err != nil {
					slog.Warn("notifier: fetch delivery state failed", "hook_id", hook.ID, "job", jobPath, "error", err)
					continue
				}
				alreadyInProgress := exists && lastBuild == build.Number && lastResult == "IN_PROGRESS"
				if !alreadyInProgress {
					if err := n.database.UpsertHookDeliveryState(hook.ID, jobPath, build.Number, "IN_PROGRESS"); err != nil {
						slog.Warn("notifier: baseline in-progress delivery state failed", "hook_id", hook.ID, "job", jobPath, "error", err)
					}
				}
				if hook.Type == "telegram" {
					if err := n.sendOrUpdateTelegramLive(hook, code.Label, jobPath, build, visibleStages, buildStatus); err != nil {
						_ = n.database.AddHookDeliveryLog(hook.ID, hook.Type, jobPath, "live", "failed", err.Error())
						slog.Warn("notifier: telegram live delivery failed", "hook_id", hook.ID, "job", jobPath, "error", err)
					} else {
						_ = n.database.AddHookDeliveryLog(hook.ID, hook.Type, jobPath, "live", "sent", "Telegram live message sent/updated.")
					}
				}
			}
			return true
		}
	}
	if !isFinalResult(build.Result) {
		return false
	}

	if build.Duration <= 0 {
		if stages, _, err := n.client.GetStages(jobPath, build.Number); err == nil {
			if duration := sumStageDurations(stages); duration > 0 {
				build.Duration = duration
			}
		}
	}

	payload := map[string]any{
		"code_label":     code.Label,
		"job_path":       jobPath,
		"build_number":   build.Number,
		"result":         build.Result,
		"timestamp":      build.Time().Format(time.RFC3339),
		"duration_ms":    build.Duration,
		"duration_human": build.DurationStr(),
		"branch":         build.BranchName,
		"commit_id":      build.CommitID,
		"commit_short":   build.ShortCommit(),
		"commit_msg":     build.CommitMsg,
		"commit_author":  build.CommitAuthor,
	}

	for _, hook := range code.Hooks {
		lastBuild, lastResult, exists, err := n.database.GetHookDeliveryState(hook.ID, jobPath)
		if err != nil {
			slog.Warn("notifier: fetch delivery state failed", "hook_id", hook.ID, "job", jobPath, "error", err)
			continue
		}
		if !exists {
			if !n.shouldSendFirstFinal(build) {
				if err := n.database.UpsertHookDeliveryState(hook.ID, jobPath, build.Number, build.Result); err != nil {
					slog.Warn("notifier: baseline delivery state failed", "hook_id", hook.ID, "job", jobPath, "error", err)
				}
				continue
			}
		}
		if lastBuild == build.Number && lastResult == build.Result {
			continue
		}

		switch hook.Type {
		case "webhook":
			if err := n.sendWebhook(hook.Value, payload); err != nil {
				_ = n.database.AddHookDeliveryLog(hook.ID, hook.Type, jobPath, "final", "failed", err.Error())
				slog.Warn("notifier: webhook delivery failed", "hook_id", hook.ID, "job", jobPath, "error", err)
				continue
			}
			_ = n.database.AddHookDeliveryLog(hook.ID, hook.Type, jobPath, "final", "sent", "Webhook notification sent.")
		case "telegram":
			if err := n.finishTelegramLive(hook, code.Label, jobPath, build); err != nil {
				_ = n.database.AddHookDeliveryLog(hook.ID, hook.Type, jobPath, "final", "failed", err.Error())
				slog.Warn("notifier: telegram delivery failed", "hook_id", hook.ID, "job", jobPath, "error", err)
				continue
			}
			_ = n.database.AddHookDeliveryLog(hook.ID, hook.Type, jobPath, "final", "sent", "Telegram final notification sent.")
		default:
			continue
		}

		if err := n.database.UpsertHookDeliveryState(hook.ID, jobPath, build.Number, build.Result); err != nil {
			slog.Warn("notifier: update delivery state failed", "hook_id", hook.ID, "job", jobPath, "error", err)
		}
	}
	return false
}

func (n *webhookNotifier) shouldSendFirstFinal(build jenkins.Build) bool {
	window := n.interval * 2
	if window < 20*time.Second {
		window = 20 * time.Second
	}
	if build.Time().IsZero() {
		return false
	}
	return time.Since(build.Time()) <= window
}

func (n *webhookNotifier) sendWebhook(target string, payload map[string]any) error {
	if err := validateWebhookTarget(target); err != nil {
		return err
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.CopyN(io.Discard, resp.Body, 1024)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &webhookError{statusCode: resp.StatusCode}
	}
	return nil
}

func (n *webhookNotifier) sendTelegram(hook appdb.Hook, codeLabel, jobPath string, build jenkins.Build) error {
	_, err := n.sendTelegramMessage(hook, telegramFinalMessage(codeLabel, jobPath, build))
	return err
}

func (n *webhookNotifier) sendTelegramTest(hook appdb.Hook, codeLabel string) error {
	_, err := n.sendTelegramMessage(hook, telegramTestMessage(codeLabel))
	return err
}

func (n *webhookNotifier) sendOrUpdateTelegramLive(hook appdb.Hook, codeLabel, jobPath string, build jenkins.Build, stages []jenkins.Stage, buildStatus string) error {
	visibleStages := visibleTelegramStages(stages)
	stageHash := telegramStageHash(build.Number, buildStatus, visibleStages)
	liveBuild, messageID, lastStageHash, _, exists, err := n.database.GetTelegramLiveState(hook.ID, jobPath)
	if err != nil {
		return err
	}
	message := telegramLiveMessage(codeLabel, jobPath, build, visibleStages, buildStatus)
	if exists && liveBuild == build.Number {
		if lastStageHash == stageHash {
			return nil
		}
		if err := n.editTelegramMessage(hook, messageID, message); err != nil {
			return err
		}
		return n.database.UpsertTelegramLiveState(hook.ID, jobPath, build.Number, messageID, stageHash, buildStatus)
	}
	messageID, err = n.sendTelegramMessage(hook, message)
	if err != nil {
		return err
	}
	return n.database.UpsertTelegramLiveState(hook.ID, jobPath, build.Number, messageID, stageHash, buildStatus)
}

func (n *webhookNotifier) finishTelegramLive(hook appdb.Hook, codeLabel, jobPath string, build jenkins.Build) error {
	liveBuild, messageID, _, _, exists, err := n.database.GetTelegramLiveState(hook.ID, jobPath)
	if err != nil {
		return err
	}
	finalMessage := telegramFinalMessage(codeLabel, jobPath, build)
	if exists && liveBuild == build.Number {
		if err := n.editTelegramMessage(hook, messageID, finalMessage); err != nil {
			return err
		}
		return n.database.DeleteTelegramLiveState(hook.ID, jobPath)
	}
	return n.sendTelegram(hook, codeLabel, jobPath, build)
}

func (n *webhookNotifier) sendTelegramMessage(hook appdb.Hook, text string) (int, error) {
	botToken := hook.Meta["bot_token"]
	chatID := hook.Meta["chat_id"]
	if botToken == "" || chatID == "" {
		return 0, &webhookError{message: "telegram hook is missing bot token or chat id"}
	}

	endpoint := "https://api.telegram.org/bot" + botToken + "/sendMessage"
	body, err := json.Marshal(map[string]any{
		"chat_id": chatID,
		"text":    text,
	})
	if err != nil {
		return 0, err
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, telegramAPIError(resp.StatusCode, raw)
	}
	var telegramResp struct {
		OK     bool `json:"ok"`
		Result struct {
			MessageID int `json:"message_id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &telegramResp); err != nil {
		return 0, err
	}
	return telegramResp.Result.MessageID, nil
}

func (n *webhookNotifier) editTelegramMessage(hook appdb.Hook, messageID int, text string) error {
	botToken := hook.Meta["bot_token"]
	chatID := hook.Meta["chat_id"]
	if botToken == "" || chatID == "" {
		return &webhookError{message: "telegram hook is missing bot token or chat id"}
	}
	endpoint := "https://api.telegram.org/bot" + botToken + "/editMessageText"
	body, err := json.Marshal(map[string]any{
		"chat_id":    chatID,
		"message_id": messageID,
		"text":       text,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := telegramAPIError(resp.StatusCode, raw)
		if isTelegramNotModified(err) {
			return nil
		}
		return err
	}
	return nil
}

func telegramFinalMessage(codeLabel, jobPath string, build jenkins.Build) string {
	statusIcon := telegramResultIcon(build.Result)
	lines := []string{
		statusIcon + " Jenkins Build Update",
		"",
		"🏷️ Label: " + codeLabel,
		"📦 Job: " + jobPath,
		"🔢 Build: #" + strconv.Itoa(build.Number),
		"📊 Result: " + build.Result,
		"⏱️ Duration: " + build.DurationStr(),
	}

	if build.BranchName != "" {
		lines = append(lines, "🌿 Branch: "+build.BranchName)
	}
	if build.ShortCommit() != "" {
		lines = append(lines, "🧬 Commit: "+build.ShortCommit())
	}
	if build.CommitMsg != "" {
		lines = append(lines, "💬 Message: "+build.CommitMsg)
	}

	return strings.Join(lines, "\n")
}

func telegramTestMessage(codeLabel string) string {
	lines := []string{
		"🧪 Jenkins Hook Test",
		"",
		"🏷️ Label: " + codeLabel,
		"📡 Status: SUCCESS",
		"📝 This is a manual Telegram hook test.",
	}
	return strings.Join(lines, "\n")
}

func telegramLiveMessage(codeLabel, jobPath string, build jenkins.Build, stages []jenkins.Stage, buildStatus string) string {
	lines := []string{
		"🔄 Jenkins Build Live",
		"",
		"🏷️ Label: " + codeLabel,
		"📦 Job: " + jobPath,
		"🔢 Build: #" + strconv.Itoa(build.Number),
		"📡 Status: " + buildStatus,
	}
	if build.BranchName != "" {
		lines = append(lines, "🌿 Branch: "+build.BranchName)
	}
	if build.ShortCommit() != "" {
		lines = append(lines, "🧬 Commit: "+build.ShortCommit())
	}
	if len(stages) > 0 {
		lines = append(lines, "")
		lines = append(lines, "🧱 Stages:")
		for _, stage := range stages {
			lines = append(lines, fmt.Sprintf("%s %s: %s", telegramStageIcon(stage.Status), stage.Name, telegramStageLabel(stage.Status)))
		}
	}
	return strings.Join(lines, "\n")
}

func telegramResultIcon(result string) string {
	switch result {
	case "SUCCESS":
		return "✅"
	case "FAILURE":
		return "❌"
	case "UNSTABLE":
		return "⚠️"
	case "ABORTED":
		return "🛑"
	default:
		return "ℹ️"
	}
}

func telegramStageIcon(status string) string {
	switch status {
	case "SUCCESS":
		return "✅"
	case "FAILED", "FAILURE":
		return "❌"
	case "UNSTABLE":
		return "⚠️"
	case "ABORTED", "NOT_EXECUTED":
		return "🛑"
	case "IN_PROGRESS", "PAUSED_PENDING_INPUT":
		return "🔄"
	default:
		return "•"
	}
}

func telegramStageLabel(status string) string {
	switch status {
	case "FAILED":
		return "FAILURE"
	default:
		return status
	}
}

func telegramStageHash(buildNumber int, buildStatus string, stages []jenkins.Stage) string {
	body, _ := json.Marshal(map[string]any{
		"build_number": buildNumber,
		"status":       buildStatus,
		"stages":       stages,
	})
	return string(body)
}

func visibleTelegramStages(stages []jenkins.Stage) []jenkins.Stage {
	filtered := make([]jenkins.Stage, 0, len(stages))
	for _, stage := range stages {
		if strings.HasPrefix(stage.Name, "Declarative:") {
			continue
		}
		filtered = append(filtered, stage)
	}
	return filtered
}

func sumStageDurations(stages []jenkins.Stage) int64 {
	var total int64
	for _, stage := range stages {
		if stage.DurationMillis > 0 {
			total += stage.DurationMillis
		}
	}
	return total
}

func isFinalResult(result string) bool {
	switch result {
	case "SUCCESS", "FAILURE", "UNSTABLE", "ABORTED":
		return true
	default:
		return false
	}
}

func validateWebhookTarget(raw string) error {
	u, err := neturl.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return &webhookError{message: "unsupported webhook scheme"}
	}
	if u.User != nil {
		return &webhookError{message: "webhook with embedded credentials is not allowed"}
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".local") {
		return &webhookError{message: "localhost webhook is not allowed"}
	}
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip) {
			return &webhookError{message: "private or local webhook target is not allowed"}
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return err
	}
	if len(addrs) == 0 {
		return &webhookError{message: "webhook host did not resolve"}
	}
	for _, addr := range addrs {
		if isBlockedIP(addr.IP) {
			return &webhookError{message: "private or local webhook target is not allowed"}
		}
	}
	return nil
}

func isBlockedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified()
}

type webhookError struct {
	statusCode int
	message    string
}

func (e *webhookError) Error() string {
	if e.message != "" {
		return e.message
	}
	return "webhook returned HTTP " + http.StatusText(e.statusCode)
}

func telegramAPIError(statusCode int, raw []byte) error {
	var apiErr struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(raw, &apiErr); err == nil && apiErr.Description != "" {
		return &webhookError{
			statusCode: statusCode,
			message:    "telegram returned HTTP " + http.StatusText(statusCode) + ": " + apiErr.Description,
		}
	}
	return &webhookError{statusCode: statusCode}
}

func isTelegramNotModified(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "message is not modified")
}
