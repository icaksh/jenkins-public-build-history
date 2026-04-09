package jenkins

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Client struct {
	BaseURL    string
	Username   string
	Token      string
	httpClient *http.Client
	mu         sync.Mutex
	jobsCache  map[string]jobsCacheEntry
	buildCache map[string]buildsCacheEntry
}

type jobsCacheEntry struct {
	expiresAt time.Time
	jobs      []Job
}

type buildsCacheEntry struct {
	expiresAt time.Time
	builds    []Build
}

func New(baseURL, username, token string) *Client {
	return &Client{
		BaseURL:  strings.TrimRight(baseURL, "/"),
		Username: username,
		Token:    token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		jobsCache:  make(map[string]jobsCacheEntry),
		buildCache: make(map[string]buildsCacheEntry),
	}
}

// jobURLPath converts "Folder/Sub/Job" → "/job/Folder/job/Sub/job/Job"
func jobURLPath(name string) string {
	parts := strings.Split(name, "/")
	var sb strings.Builder
	for _, p := range parts {
		sb.WriteString("/job/")
		sb.WriteString(url.PathEscape(p))
	}
	return sb.String()
}

func (c *Client) newRequest(method, path string) (*http.Request, error) {
	req, err := http.NewRequest(method, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if c.Username != "" && c.Token != "" {
		req.SetBasicAuth(c.Username, c.Token)
	}
	return req, nil
}

// Job represents a Jenkins job or folder item.
type Job struct {
	Class       string `json:"_class"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	URL         string `json:"url"`
	Color       string `json:"color"`
}

func (j Job) IsFolder() bool {
	return strings.Contains(j.Class, "Folder") || strings.Contains(j.Class, "folder")
}

type jobsResponse struct {
	Jobs []Job `json:"jobs"`
}

// GetJobs returns jobs/folders at the root level.
func (c *Client) GetJobs() ([]Job, error) {
	return c.getJobsAt("")
}

// GetJobsInFolder returns jobs/folders inside a folder path (e.g. "hisv3" or "hisv3/Env-QA").
func (c *Client) GetJobsInFolder(folderPath string) ([]Job, error) {
	return c.getJobsAt(folderPath)
}

func (c *Client) getJobsAt(path string) ([]Job, error) {
	if jobs, ok := c.cachedJobs(path); ok {
		return jobs, nil
	}
	apiPath := "/"
	if path != "" {
		apiPath = jobURLPath(path) + "/"
	}
	req, err := c.newRequest("GET", apiPath+"api/json?tree=jobs[_class,name,displayName,url,color]")
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("path '%s' not found", path)
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, fmt.Errorf("authentication failed (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("jenkins returned HTTP %d", resp.StatusCode)
	}
	var result jobsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	c.storeJobs(path, result.Jobs)
	return result.Jobs, nil
}

func (c *Client) cachedJobs(path string) ([]Job, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.jobsCache[path]
	if !ok || time.Now().After(entry.expiresAt) {
		if ok {
			delete(c.jobsCache, path)
		}
		return nil, false
	}
	return append([]Job(nil), entry.jobs...), true
}

func (c *Client) storeJobs(path string, jobs []Job) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.jobsCache[path] = jobsCacheEntry{
		expiresAt: time.Now().Add(10 * time.Second),
		jobs:      append([]Job(nil), jobs...),
	}
}

// Build represents a single Jenkins build.
type Build struct {
	Number       int    `json:"number"`
	Result       string `json:"result"`
	Timestamp    int64  `json:"timestamp"`
	URL          string `json:"url"`
	Duration     int64  `json:"duration"`
	Building     bool   `json:"building"`
	DisplayName  string `json:"displayName"`
	CommitID     string
	CommitMsg    string
	CommitAuthor string
	BranchName   string
}

func (b Build) Time() time.Time {
	return time.UnixMilli(b.Timestamp)
}

func (b Build) DurationStr() string {
	d := time.Duration(b.Duration) * time.Millisecond
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}

func (b Build) StatusClass() string {
	switch b.Result {
	case "SUCCESS":
		return "success"
	case "FAILURE":
		return "failure"
	case "UNSTABLE":
		return "unstable"
	case "ABORTED":
		return "aborted"
	default:
		if b.Building {
			return "building"
		}
		return "unknown"
	}
}

func (b Build) StatusIcon() string {
	switch b.Result {
	case "SUCCESS":
		return "fa-circle-check"
	case "FAILURE":
		return "fa-circle-xmark"
	case "UNSTABLE":
		return "fa-triangle-exclamation"
	case "ABORTED":
		return "fa-ban"
	default:
		if b.Building {
			return "fa-spinner fa-spin"
		}
		return "fa-circle-question"
	}
}

func (b Build) ShortCommit() string {
	if len(b.CommitID) > 7 {
		return b.CommitID[:7]
	}
	return b.CommitID
}

type buildsResponse struct {
	Builds []buildAPIResponse `json:"builds"`
}

type buildAPIResponse struct {
	Number      int           `json:"number"`
	Result      string        `json:"result"`
	Timestamp   int64         `json:"timestamp"`
	URL         string        `json:"url"`
	Duration    int64         `json:"duration"`
	Building    bool          `json:"building"`
	DisplayName string        `json:"displayName"`
	ChangeSets  []changeSet   `json:"changeSets"`
	Actions     []buildAction `json:"actions"`
}

func buildFromAPIResponse(item buildAPIResponse) Build {
	build := Build{
		Number:      item.Number,
		Result:      item.Result,
		Timestamp:   item.Timestamp,
		URL:         item.URL,
		Duration:    item.Duration,
		Building:    item.Building,
		DisplayName: item.DisplayName,
	}

	build.Result, build.Building = normalizeBuildState(item.Result, item.Building, "")

	for _, cs := range item.ChangeSets {
		if len(cs.Items) == 0 {
			continue
		}
		change := cs.Items[0]
		build.CommitID = change.CommitID
		build.CommitMsg = strings.TrimSpace(change.Msg)
		build.CommitAuthor = change.Author.FullName
		break
	}
	for _, action := range item.Actions {
		if action.LastBuiltRevision == nil {
			continue
		}
		if build.CommitID == "" {
			build.CommitID = action.LastBuiltRevision.SHA1
		}
		if len(action.LastBuiltRevision.Branch) > 0 {
			build.BranchName = action.LastBuiltRevision.Branch[0].Name
		}
		break
	}

	return build
}

func normalizeBuildState(listResult string, listBuilding bool, wfapiStatus string) (string, bool) {
	if listResult != "" {
		return listResult, false
	}
	switch wfapiStatus {
	case "SUCCESS":
		return "SUCCESS", false
	case "FAILED", "FAILURE":
		return "FAILURE", false
	case "UNSTABLE":
		return "UNSTABLE", false
	case "ABORTED":
		return "ABORTED", false
	case "IN_PROGRESS", "PAUSED_PENDING_INPUT":
		return "", true
	}
	// No result from either source yet — keep treating as building so the
	// notifier retries until Jenkins provides a definitive result.
	return "", listBuilding
}

type changeSet struct {
	Items []changeSetItem `json:"items"`
}

type changeSetItem struct {
	CommitID string `json:"commitId"`
	Msg      string `json:"msg"`
	Author   struct {
		FullName string `json:"fullName"`
	} `json:"author"`
}

type buildAction struct {
	LastBuiltRevision *lastBuiltRevision `json:"lastBuiltRevision"`
}

type lastBuiltRevision struct {
	SHA1   string         `json:"SHA1"`
	Branch []branchRecord `json:"branch"`
}

type branchRecord struct {
	Name string `json:"name"`
}

func (c *Client) GetBuilds(jobName string, limit int) ([]Build, error) {
	cacheKey := fmt.Sprintf("%s|%d", jobName, limit)
	if builds, ok := c.cachedBuilds(cacheKey); ok {
		return builds, nil
	}
	path := jobURLPath(jobName) + "/api/json?tree=builds[number,result,timestamp,url,duration,building,displayName,changeSets[items[commitId,msg,author[fullName]]],actions[lastBuiltRevision[SHA1,branch[name]]]]"
	req, err := c.newRequest("GET", path)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("job '%s' not found", jobName)
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, fmt.Errorf("authentication failed (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("jenkins returned HTTP %d", resp.StatusCode)
	}
	var result buildsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	builds := make([]Build, 0, len(result.Builds))
	for _, item := range result.Builds {
		build := buildFromAPIResponse(item)

		if item.Building || item.Result == "" {
			if _, wfapiStatus, err := c.GetStages(jobName, item.Number); err == nil {
				build.Result, build.Building = normalizeBuildState(item.Result, item.Building, wfapiStatus)
			} else {
				build.Result, build.Building = normalizeBuildState(item.Result, item.Building, "")
			}
		}

		builds = append(builds, build)
	}

	if limit > 0 && len(builds) > limit {
		builds = builds[:limit]
	}
	c.storeBuilds(cacheKey, builds)
	return builds, nil
}

func (c *Client) GetBuild(jobName string, buildNumber int) (Build, error) {
	path := fmt.Sprintf("%s/%d/api/json?tree=number,result,timestamp,url,duration,building,displayName,changeSets[items[commitId,msg,author[fullName]]],actions[lastBuiltRevision[SHA1,branch[name]]]]", jobURLPath(jobName), buildNumber)
	req, err := c.newRequest("GET", path)
	if err != nil {
		return Build{}, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Build{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return Build{}, fmt.Errorf("jenkins returned HTTP %d", resp.StatusCode)
	}
	var item buildAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&item); err != nil {
		return Build{}, err
	}
	return buildFromAPIResponse(item), nil
}

func (c *Client) GetBuildConsoleResult(jobName string, buildNumber int) (string, error) {
	path := fmt.Sprintf("%s/%d/consoleText", jobURLPath(jobName), buildNumber)
	req, err := c.newRequest("GET", path)
	if err != nil {
		return "", err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("jenkins returned HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	return detectConsoleResult(string(raw)), nil
}

func detectConsoleResult(text string) string {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		switch {
		case strings.HasPrefix(line, "Finished: SUCCESS"):
			return "SUCCESS"
		case strings.HasPrefix(line, "Finished: FAILURE"):
			return "FAILURE"
		case strings.HasPrefix(line, "Finished: UNSTABLE"):
			return "UNSTABLE"
		case strings.HasPrefix(line, "Finished: ABORTED"):
			return "ABORTED"
		}
	}
	return ""
}

func (c *Client) cachedBuilds(key string) ([]Build, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.buildCache[key]
	if !ok || time.Now().After(entry.expiresAt) {
		if ok {
			delete(c.buildCache, key)
		}
		return nil, false
	}
	return append([]Build(nil), entry.builds...), true
}

func (c *Client) storeBuilds(key string, builds []Build) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buildCache[key] = buildsCacheEntry{
		expiresAt: time.Now().Add(2 * time.Second),
		builds:    append([]Build(nil), builds...),
	}
}

// Stage represents a single pipeline stage from /wfapi/describe.
type Stage struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Status         string `json:"status"`
	DurationMillis int64  `json:"durationMillis"`
}

func (s Stage) StatusClass() string {
	switch s.Status {
	case "SUCCESS":
		return "success"
	case "FAILED":
		return "failure"
	case "UNSTABLE":
		return "unstable"
	case "ABORTED":
		return "aborted"
	case "IN_PROGRESS":
		return "building"
	case "NOT_EXECUTED":
		return "aborted"
	default:
		return "unknown"
	}
}

func (s Stage) StatusIcon() string {
	switch s.Status {
	case "SUCCESS":
		return "fa-circle-check"
	case "FAILED":
		return "fa-circle-xmark"
	case "UNSTABLE":
		return "fa-triangle-exclamation"
	case "ABORTED", "NOT_EXECUTED":
		return "fa-ban"
	case "IN_PROGRESS":
		return "fa-spinner fa-spin"
	default:
		return "fa-circle-question"
	}
}

func (s Stage) DurationStr() string {
	d := time.Duration(s.DurationMillis) * time.Millisecond
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}

type wfapiResponse struct {
	Status string  `json:"status"`
	Stages []Stage `json:"stages"`
}

func (c *Client) GetStages(jobName string, buildNumber int) ([]Stage, string, error) {
	path := fmt.Sprintf("%s/%d/wfapi/describe", jobURLPath(jobName), buildNumber)
	req, err := c.newRequest("GET", path)
	if err != nil {
		return nil, "", err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("wfapi returned HTTP %d", resp.StatusCode)
	}
	var result wfapiResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, "", err
	}
	return result.Stages, result.Status, nil
}

// StreamStagesSSE polls wfapi/describe and calls onUpdate until the build finishes.
func (c *Client) StreamStagesSSE(jobName string, buildNumber int, onUpdate func(stages []Stage, buildStatus string, done bool)) error {
	pollClient := &http.Client{Timeout: 10 * time.Second}
	_ = pollClient

	for {
		stages, status, err := c.GetStages(jobName, buildNumber)
		if err != nil {
			return err
		}
		done := status != "IN_PROGRESS" && status != "PAUSED_PENDING_INPUT"
		onUpdate(stages, status, done)
		if done {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
}
