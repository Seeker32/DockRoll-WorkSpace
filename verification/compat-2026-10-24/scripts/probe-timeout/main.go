// Command timeoutprobe records what os/exec.CommandContext does to a Compose CLI
// process on timeout/cancel, and what daemon-side state remains afterwards.
//
// It is intentionally dependency-free so it can be built with the pinned Go
// toolchain and read as a minimal reference for the recovery design.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type commandResult struct {
	Command      []string `json:"command"`
	ExitCode     int      `json:"exit_code"`
	DurationMS   int64    `json:"duration_ms"`
	Err          string   `json:"err,omitempty"`
	ProcessState string   `json:"process_state,omitempty"`
	Stdout       string   `json:"stdout,omitempty"`
	Stderr       string   `json:"stderr,omitempty"`
}

type scenarioResult struct {
	Scenario         string        `json:"scenario"`
	Mode             string        `json:"mode"`
	ComposeVersion   string        `json:"compose_version"`
	ComposeConfig    string        `json:"compose_config"`
	Project          string        `json:"project"`
	TimeoutMS        int64         `json:"timeout_ms"`
	TimedOut         bool          `json:"timed_out"`
	ContextError     string        `json:"context_error"`
	DurationMS       int64         `json:"duration_ms"`
	Wait             commandResult `json:"wait"`
	StateAfter       commandResult `json:"state_after_ps_all"`
	StateAfterPlain  commandResult `json:"state_after_ps"`
	DockerPsAfter    commandResult `json:"docker_ps_after"`
	ContainerFound   bool          `json:"container_found_after_timeout"`
	ContainerNames   []string      `json:"container_names_after_timeout"`
	Cleanup          commandResult `json:"cleanup_down"`
	CleanupRemaining commandResult `json:"cleanup_remaining"`
	CleanupVerified  bool          `json:"cleanup_verified"`
	StartedAt        string        `json:"started_at"`
	FinishedAt       string        `json:"finished_at"`
}

func run(ctx context.Context, args []string, cancelMode string, waitDelay time.Duration) commandResult {
	started := time.Now()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	if cancelMode == "interrupt" {
		cmd.Cancel = func() error {
			if cmd.Process == nil {
				return os.ErrProcessDone
			}
			return cmd.Process.Signal(os.Interrupt)
		}
		cmd.WaitDelay = waitDelay
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	result := commandResult{
		Command:    args,
		DurationMS: time.Since(started).Milliseconds(),
		Stdout:     stdout.String(),
		Stderr:     stderr.String(),
	}
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
		result.ProcessState = cmd.ProcessState.String()
	} else {
		result.ExitCode = -1
	}
	if err != nil {
		result.Err = err.Error()
	}
	return result
}

func composeArgs(docker, project, composeFile string, args ...string) []string {
	base := []string{docker, "compose", "-p", project, "-f", composeFile,
		"--project-directory", filepath.Dir(composeFile)}
	base = append(base, args...)
	return base
}

func version(ctx context.Context, docker string) string {
	result := run(ctx, []string{docker, "compose", "version", "--short"}, "kill", 0)
	return strings.TrimSpace(result.Stdout)
}

func containersByProject(ctx context.Context, docker, project string) commandResult {
	return run(ctx, []string{docker, "ps", "-a",
		"--filter", "label=com.docker.compose.project=" + project,
		"--format", "{{.Names}}"}, "kill", 0)
}

func names(output string) []string {
	var result []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

func main() {
	mode := flag.String("mode", "kill", "kill|interrupt")
	project := flag.String("project", "ota-compat-timeout", "Compose project name")
	composeFile := flag.String("compose-file", "", "absolute path to compose-timeout.yaml")
	docker := flag.String("docker", "docker", "docker CLI")
	timeout := flag.Duration("timeout", 3*time.Second, "context timeout before cancel")
	jsonOut := flag.String("json", "", "write JSON result to this path")
	cleanup := flag.Bool("cleanup", true, "run compose down after capturing state")
	flag.Parse()
	if *composeFile == "" {
		fmt.Fprintln(os.Stderr, "-compose-file is required")
		os.Exit(2)
	}
	absCompose, err := filepath.Abs(*composeFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	bg := context.Background()
	composeVersion := version(bg, *docker)
	startedAt := time.Now().UTC().Format(time.RFC3339Nano)

	ctx, cancel := context.WithTimeout(bg, *timeout)
	defer cancel()
	wait := run(ctx, composeArgs(*docker, *project, absCompose, "up", "-d", "--wait", "--wait-timeout", "60"),
		*mode, 10*time.Second)
	contextErr := "nil"
	if err := ctx.Err(); err != nil {
		contextErr = err.Error()
	}

	stateCtx, stateCancel := context.WithTimeout(bg, 60*time.Second)
	defer stateCancel()
	stateAll := run(stateCtx, composeArgs(*docker, *project, absCompose, "ps", "--all", "--format", "json"), "kill", 0)
	statePlain := run(stateCtx, composeArgs(*docker, *project, absCompose, "ps", "--format", "json"), "kill", 0)
	dockerPs := containersByProject(stateCtx, *docker, *project)
	containerNames := names(dockerPs.Stdout)

	result := scenarioResult{
		Scenario:        "compose-up-wait-timeout",
		Mode:            *mode,
		ComposeVersion:  composeVersion,
		ComposeConfig:   absCompose,
		Project:         *project,
		TimeoutMS:       timeout.Milliseconds(),
		TimedOut:        contextErr == context.DeadlineExceeded.Error(),
		ContextError:    contextErr,
		DurationMS:      wait.DurationMS,
		Wait:            wait,
		StateAfter:      stateAll,
		StateAfterPlain: statePlain,
		DockerPsAfter:   dockerPs,
		ContainerFound:  len(containerNames) > 0,
		ContainerNames:  containerNames,
		StartedAt:       startedAt,
	}

	if *cleanup {
		cleanupCtx, cleanupCancel := context.WithTimeout(bg, 120*time.Second)
		defer cleanupCancel()
		result.Cleanup = run(cleanupCtx, composeArgs(*docker, *project, absCompose, "down"), "kill", 0)
		result.CleanupRemaining = containersByProject(cleanupCtx, *docker, *project)
		result.CleanupVerified = len(names(result.CleanupRemaining.Stdout)) == 0
	}
	result.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)

	encoded, _ := json.MarshalIndent(result, "", "  ")
	if *jsonOut != "" {
		if err := os.WriteFile(*jsonOut, encoded, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "write json:", err)
			os.Exit(1)
		}
	}
	fmt.Printf("scenario=%s mode=%s compose=%s\n", result.Scenario, result.Mode, result.ComposeVersion)
	fmt.Printf("timed_out=%s ctx=%s wait_exit=%d wait_err=%s duration_ms=%d\n",
		strconv.FormatBool(result.TimedOut), result.ContextError, result.Wait.ExitCode,
		result.Wait.Err, result.Wait.DurationMS)
	fmt.Printf("process_state=%q containers_after_timeout=%v names=%v\n",
		result.Wait.ProcessState, result.ContainerFound, result.ContainerNames)
	fmt.Printf("docker_ps_exit=%d cleanup_down_exit=%d cleanup_verified=%v remaining=%q\n",
		result.DockerPsAfter.ExitCode, result.Cleanup.ExitCode, result.CleanupVerified,
		strings.TrimSpace(result.CleanupRemaining.Stdout))
	if !result.TimedOut {
		fmt.Fprintln(os.Stderr, "warning: scenario did not observe context deadline exceeded")
		os.Exit(1)
	}
	if !result.ContainerFound {
		fmt.Fprintln(os.Stderr, "warning: expected daemon-side container after cancelled up --wait")
		os.Exit(1)
	}
	if *cleanup && !result.CleanupVerified {
		fmt.Fprintln(os.Stderr, "warning: cleanup did not remove all project containers")
		os.Exit(1)
	}
}
