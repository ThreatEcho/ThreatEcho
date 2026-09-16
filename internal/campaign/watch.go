// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// DefaultWatchInterval is the polling interval used when WatchOptions.Interval
// is zero or negative.
const DefaultWatchInterval = 2 * time.Second

// WatchOptions configures the campaign file watcher.
type WatchOptions struct {
	// Dir is the directory to watch for campaign subdirectories.
	// Each immediate subdirectory containing a campaign.yaml is monitored.
	Dir string

	// Interval is the polling interval. Defaults to DefaultWatchInterval (2s).
	Interval time.Duration

	// OnChange is called for each detected campaign file change.
	OnChange func(event WatchEvent)

	// OnError is called when a non-fatal error occurs during polling
	// (e.g. the directory becomes temporarily unreadable on a VirtualBox
	// shared folder). If nil, polling errors are silently ignored.
	OnError func(err error)

	// Validate runs structural validation on changed campaigns.
	Validate bool

	// Lint runs quality checks on changed campaigns.
	Lint bool

	// Format checks whether the file matches canonical formatting.
	Format bool
}

// WatchEvent describes a detected change in a campaign file.
type WatchEvent struct {
	// Path is the absolute filesystem path of the campaign.yaml file.
	Path string

	// Campaign is the campaign name extracted from meta.name.
	Campaign string

	// Type is one of "modified", "added", or "removed".
	Type string

	// Errors holds validation errors when WatchOptions.Validate is true.
	// Empty when the campaign passes validation or Validate is false.
	Errors []error

	// LintResult holds lint output when WatchOptions.Lint is true.
	// Nil when Lint is false.
	LintResult *LintResult

	// FormatDrift is true when the file content differs from canonical
	// formatting. Only set when WatchOptions.Format is true.
	FormatDrift bool
}

// fileState tracks the last-observed state of a campaign.yaml file.
type fileState struct {
	modTime  time.Time
	size     int64
	campaign string // meta.name at last scan
}

// Watch polls Dir for campaign.yaml file changes and calls OnChange for each
// detected addition, modification, or removal. It blocks until ctx is
// cancelled, returning ctx.Err().
//
// The first scan establishes a baseline without firing events. Subsequent
// polls detect changes relative to the tracked state.
//
// Only campaign.yaml files in immediate subdirectories of Dir are watched.
// The implementation uses os.Stat polling with no external dependencies,
// which works reliably on VirtualBox shared folders where inotify/fsnotify
// is unavailable.
func Watch(ctx context.Context, opts WatchOptions) error {
	if opts.Dir == "" {
		return fmt.Errorf("watch: Dir is required")
	}
	if opts.OnChange == nil {
		return fmt.Errorf("watch: OnChange callback is required")
	}
	if opts.Interval <= 0 {
		opts.Interval = DefaultWatchInterval
	}
	if opts.OnError == nil {
		opts.OnError = func(error) {}
	}

	// Initial scan — build baseline without firing events.
	tracked := make(map[string]*fileState)
	if err := scanCampaigns(opts.Dir, tracked); err != nil {
		opts.OnError(err)
	}

	ticker := time.NewTicker(opts.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			pollChanges(opts, tracked)
		}
	}
}

// scanCampaigns discovers campaign.yaml files in immediate subdirectories
// of dir and records their state in tracked. No events are generated.
func scanCampaigns(dir string, tracked map[string]*fileState) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("scanning watch directory %q: %w", dir, err)
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name(), "campaign.yaml")
		info, err := os.Stat(p)
		if err != nil {
			continue // no campaign.yaml in this subdirectory
		}
		tracked[p] = &fileState{
			modTime:  info.ModTime(),
			size:     info.Size(),
			campaign: extractCampaignName(p),
		}
	}
	return nil
}

// pollChanges compares the current filesystem state against tracked state.
// It fires events for additions, modifications, and removals, then updates
// the tracked map to reflect the new state.
func pollChanges(opts WatchOptions, tracked map[string]*fileState) {
	entries, err := os.ReadDir(opts.Dir)
	if err != nil {
		opts.OnError(fmt.Errorf("polling watch directory %q: %w", opts.Dir, err))
		return
	}

	seen := make(map[string]bool)

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		p := filepath.Join(opts.Dir, e.Name(), "campaign.yaml")
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		seen[p] = true

		prev, existed := tracked[p]
		if !existed {
			// New campaign file.
			name := extractCampaignName(p)
			tracked[p] = &fileState{
				modTime:  info.ModTime(),
				size:     info.Size(),
				campaign: name,
			}
			evt := WatchEvent{Path: p, Campaign: name, Type: "added"}
			applyChecks(&evt, opts)
			opts.OnChange(evt)
		} else if info.ModTime() != prev.modTime || info.Size() != prev.size {
			// Modified campaign file.
			name := extractCampaignName(p)
			tracked[p] = &fileState{
				modTime:  info.ModTime(),
				size:     info.Size(),
				campaign: name,
			}
			evt := WatchEvent{Path: p, Campaign: name, Type: "modified"}
			applyChecks(&evt, opts)
			opts.OnChange(evt)
		}
	}

	// Detect removals — tracked files not seen in this poll.
	for p, prev := range tracked {
		if !seen[p] {
			delete(tracked, p)
			evt := WatchEvent{
				Path:     p,
				Campaign: prev.campaign,
				Type:     "removed",
			}
			opts.OnChange(evt)
		}
	}
}

// applyChecks runs validation, lint, and format checks on a campaign file
// and populates the corresponding event fields.
func applyChecks(evt *WatchEvent, opts WatchOptions) {
	if opts.Validate || opts.Lint {
		c, err := Load(evt.Path)
		if err != nil {
			if opts.Validate {
				evt.Errors = []error{fmt.Errorf("load failed: %w", err)}
			}
			// Cannot lint or validate a campaign that fails to load.
		} else {
			if opts.Validate {
				for _, issue := range Validate(c) {
					evt.Errors = append(evt.Errors, fmt.Errorf("%s", issue))
				}
			}
			if opts.Lint {
				evt.LintResult = Lint(c)
			}
		}
	}

	if opts.Format {
		formatted, err := FormatFile(evt.Path)
		if err != nil {
			return // cannot determine format drift
		}
		raw, err := os.ReadFile(evt.Path)
		if err != nil {
			return
		}
		evt.FormatDrift = !bytes.Equal(raw, formatted)
	}
}

// extractCampaignName loads just the campaign name from a YAML file.
// Returns an empty string on any error.
func extractCampaignName(path string) string {
	c, err := loadRaw(path)
	if err != nil {
		return ""
	}
	return c.Meta.Name
}
