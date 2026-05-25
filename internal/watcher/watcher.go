// Package watcher monitors a directory tree for file changes and fires a
// debounced callback. It is used by `trojan scan --watch` to trigger
// re-scans without hammering the scanner on every keystroke.
package watcher

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

const debounceDelay = 1500 * time.Millisecond

// ignoredDirs are directories we never watch — they change constantly and
// are irrelevant to security scans.
var ignoredDirs = []string{
	".git",
	".trojan",
	"node_modules",
	"vendor",
	".venv",
	"__pycache__",
	".mypy_cache",
	".pytest_cache",
	"dist",
	"build",
	".next",
	".nuxt",
	"target", // Rust/Java build output
}

// ignoredExts are file extensions we skip — binary, compiled, or temp files.
var ignoredExts = []string{
	".tmp", ".swp", ".swo", ".DS_Store",
	".pyc", ".pyo", ".class", ".o", ".a", ".so",
	".exe", ".dll", ".dylib",
}

// Watcher watches a directory tree and calls onChange after a debounce
// window with no further events. Stop must be called to release resources.
type Watcher struct {
	fw       *fsnotify.Watcher
	onChange func()
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// New creates a Watcher rooted at dir. onChange is called at most once per
// debounceDelay window. Call Stop() to clean up.
func New(dir string, onChange func()) (*Watcher, error) {
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	w := &Watcher{
		fw:       fw,
		onChange: onChange,
		stopCh:   make(chan struct{}),
	}

	if err := w.addRecursive(dir); err != nil {
		fw.Close()
		return nil, err
	}

	w.wg.Add(1)
	go w.run()

	return w, nil
}

// Stop shuts down the watcher and waits for the goroutine to exit.
func (w *Watcher) Stop() {
	close(w.stopCh)
	w.fw.Close()
	w.wg.Wait()
}

// run is the main event loop. It debounces rapid file events and also
// dynamically adds newly created directories to the watch list.
func (w *Watcher) run() {
	defer w.wg.Done()

	var (
		timer   *time.Timer
		timerMu sync.Mutex
	)

	resetTimer := func() {
		timerMu.Lock()
		defer timerMu.Unlock()
		if timer != nil {
			timer.Reset(debounceDelay)
		} else {
			timer = time.AfterFunc(debounceDelay, func() {
				timerMu.Lock()
				timer = nil
				timerMu.Unlock()
				w.onChange()
			})
		}
	}

	for {
		select {
		case <-w.stopCh:
			timerMu.Lock()
			if timer != nil {
				timer.Stop()
			}
			timerMu.Unlock()
			return

		case event, ok := <-w.fw.Events:
			if !ok {
				return
			}
			if shouldIgnore(event.Name) {
				continue
			}
			// Newly created directories need to be watched too.
			if event.Has(fsnotify.Create) {
				if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
					_ = w.addRecursive(event.Name)
				}
			}
			resetTimer()

		case _, ok := <-w.fw.Errors:
			if !ok {
				return
			}
			// Watcher errors are non-fatal; continue watching.
		}
	}
}

// addRecursive walks dir and adds every non-ignored subdirectory to the
// fsnotify watcher.
func (w *Watcher) addRecursive(dir string) error {
	return filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable paths
		}
		if !d.IsDir() {
			return nil
		}
		if isIgnoredDir(d.Name()) {
			return filepath.SkipDir
		}
		return w.fw.Add(path)
	})
}

// shouldIgnore returns true for paths we don't want to trigger re-scans on.
func shouldIgnore(name string) bool {
	base := filepath.Base(name)

	// Hidden files (e.g. editor swap files)
	if strings.HasPrefix(base, ".") && base != "." {
		return true
	}

	// Ignored extensions
	ext := strings.ToLower(filepath.Ext(base))
	for _, ig := range ignoredExts {
		if ext == ig {
			return true
		}
	}

	// Ignored directory segments anywhere in the path
	for _, seg := range ignoredDirs {
		// Use separator-bounded check to avoid partial matches
		if strings.Contains(name, string(filepath.Separator)+seg+string(filepath.Separator)) ||
			strings.HasSuffix(name, string(filepath.Separator)+seg) {
			return true
		}
	}

	return false
}

// isIgnoredDir returns true when a directory name should be skipped entirely.
func isIgnoredDir(name string) bool {
	for _, ig := range ignoredDirs {
		if name == ig {
			return true
		}
	}
	return false
}
