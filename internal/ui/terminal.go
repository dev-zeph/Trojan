package ui

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

const (
	barWidth = 20
	boxWidth = 49 // visual width of box including ┌ and ┐
)

var (
	criticalStyle = color.New(color.FgRed, color.Bold)
	highStyle     = color.New(color.FgHiRed)
	mediumStyle   = color.New(color.FgYellow)
	lowStyle      = color.New(color.FgBlue)
	greenStyle    = color.New(color.FgGreen)
)

// PrintBanner prints the TROJAN ASCII wordmark with version.
// Call at the start of interactive commands (scan, dast, init, login, update).
func PrintBanner(version string) {
	fmt.Println()
	fmt.Println("  ████████╗██████╗  ██████╗      ██╗ █████╗ ███╗   ██╗")
	fmt.Println("  ╚══██╔══╝██╔══██╗██╔═══██╗     ██║██╔══██╗████╗  ██║")
	fmt.Println("     ██║   ██████╔╝██║   ██║     ██║███████║██╔██╗ ██║")
	fmt.Println("     ██║   ██╔══██╗██║   ██║██   ██║██╔══██║██║╚██╗██║")
	fmt.Println("     ██║   ██║  ██║╚██████╔╝╚█████╔╝██║  ██║██║ ╚████║")
	fmt.Printf("     ╚═╝   ╚═╝  ╚═╝ ╚═════╝  ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝   v%s\n", version)
	fmt.Println()
}

// PrintScanHeader prints the ┌─ Scan ─┐ metadata box.
func PrintScanHeader(target string) {
	now := time.Now().Format("02 Jan 2006  15:04")
	printTitledBox("Scan", []string{
		fmt.Sprintf("  Target   %s", target),
		fmt.Sprintf("  Started  %s", now),
	})
	fmt.Println()
}

// printTitledBox renders:
//
//	┌─ Title ──────────────────────────────────┐
//	│  line 1                                  │
//	│  line 2                                  │
//	└──────────────────────────────────────────┘
func printTitledBox(title string, lines []string) {
	titlePart := "─ " + title + " "
	fill := boxWidth - 1 - len(titlePart) - 1
	if fill < 0 {
		fill = 0
	}
	fmt.Printf("  ┌%s%s┐\n", titlePart, strings.Repeat("─", fill))

	inner := boxWidth - 2
	for _, l := range lines {
		pad := inner - len(l)
		if pad < 0 {
			pad = 0
		}
		fmt.Printf("  │%s%s│\n", l, strings.Repeat(" ", pad))
	}
	fmt.Printf("  └%s┘\n", strings.Repeat("─", boxWidth-2))
}

// ─── Scanner progress ────────────────────────────────────────────────────────

// ScanProgress manages a live-updating list of scanner rows.
// An animation goroutine re-renders all rows every 80ms — running rows show
// a bouncing snake bar; completed rows show a full bar with finding count.
type ScanProgress struct {
	mu        sync.Mutex
	names     []string
	done      []bool
	counts    []int
	errs      []error
	startTime time.Time
}

// NewScanProgress creates a ScanProgress for the given scanner names in order.
func NewScanProgress(names []string) *ScanProgress {
	return &ScanProgress{
		names:  names,
		done:   make([]bool, len(names)),
		counts: make([]int, len(names)),
		errs:   make([]error, len(names)),
	}
}

// Start prints all scanner rows and launches the animation goroutine.
func (sp *ScanProgress) Start() {
	sp.mu.Lock()
	sp.startTime = time.Now()
	for _, name := range sp.names {
		fmt.Printf("  %-10s  %s  running...\n", name, emptyBar())
	}
	sp.mu.Unlock()
	go sp.animate()
}

// Update marks the named scanner as done. The animation goroutine will
// render its final state within the next tick (~80ms).
func (sp *ScanProgress) Update(name string, count int, err error) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	for i, n := range sp.names {
		if n == name {
			sp.done[i] = true
			sp.counts[i] = count
			sp.errs[i] = err
			return
		}
	}
}

// animate ticks every 80ms and re-renders all rows in place.
// Stops once all scanners have reported done.
func (sp *ScanProgress) animate() {
	ticker := time.NewTicker(80 * time.Millisecond)
	defer ticker.Stop()
	frame := 0
	for range ticker.C {
		frame++
		sp.mu.Lock()
		allDone := sp.renderAll(frame)
		sp.mu.Unlock()
		if allDone {
			return
		}
	}
}

// renderAll re-renders every row in place using ANSI cursor movement.
// Must be called with sp.mu held. Returns true when all scanners are done.
func (sp *ScanProgress) renderAll(frame int) bool {
	n := len(sp.names)
	// Move cursor to the top of the block (n lines up from below last row).
	fmt.Printf("\033[%dA", n)
	allDone := true
	for i, name := range sp.names {
		fmt.Printf("\r\033[K") // clear line
		if sp.done[i] {
			sp.printRow(i)
		} else {
			allDone = false
			elapsed := time.Since(sp.startTime).Round(time.Second)
			fmt.Printf("  %-10s  %s  running...  %s\n", name, snakeBar(frame), elapsed)
		}
	}
	return allDone
}

func (sp *ScanProgress) printRow(idx int) {
	name := sp.names[idx]
	if sp.errs[idx] != nil {
		color.Red("  %-10s  %s  failed\n", name, emptyBar())
		return
	}
	n := sp.counts[idx]
	var suffix string
	if n == 1 {
		suffix = "done · 1 finding"
	} else {
		suffix = fmt.Sprintf("done · %d findings", n)
	}
	greenStyle.Printf("  %-10s  %s  %s\n", name, fullBar(), suffix)
}

// snakeBar returns a barWidth-wide bar with a 3-rune block bouncing left-right.
func snakeBar(frame int) string {
	const blockSize = 3
	maxPos := barWidth - blockSize // 0..17
	cycle := maxPos * 2            // 34 frames per full bounce
	pos := frame % cycle
	if pos > maxPos {
		pos = cycle - pos
	}
	bar := []rune(strings.Repeat("░", barWidth))
	for i := pos; i < pos+blockSize; i++ {
		bar[i] = '█'
	}
	return string(bar)
}

func emptyBar() string { return strings.Repeat("░", barWidth) }
func fullBar() string  { return strings.Repeat("█", barWidth) }

// ─── Results box ─────────────────────────────────────────────────────────────

// PrintResultsBox prints the ┌─ Results ─┐ severity summary box.
// counts keys: "critical", "high", "medium", "low", "info".
func PrintResultsBox(counts map[string]int) {
	fmt.Println()

	c := counts["critical"]
	h := counts["high"]
	m := counts["medium"]
	l := counts["low"]
	i := counts["info"]
	total := c + h + m + l + i

	if total == 0 {
		greenStyle.Println("  No findings. Your code looks clean!")
		fmt.Println()
		return
	}

	// Plain version for padding calculation (no ANSI codes).
	plain := buildSeverityPlain(c, h, m, l, i)
	// Colored version for actual output.
	colored := buildSeverityColored(c, h, m, l, i)

	inner := boxWidth - 2       // chars between │ and │
	contentLen := 2 + len(plain) // "  " prefix + visible text
	pad := inner - contentLen
	if pad < 0 {
		pad = 0
	}

	titlePart := "─ Results "
	fill := boxWidth - 1 - len(titlePart) - 1
	if fill < 0 {
		fill = 0
	}
	fmt.Printf("  ┌%s%s┐\n", titlePart, strings.Repeat("─", fill))
	fmt.Printf("  │  %s%s│\n", colored, strings.Repeat(" ", pad))
	fmt.Printf("  └%s┘\n", strings.Repeat("─", boxWidth-2))
	fmt.Println()
}

func buildSeverityPlain(c, h, m, l, i int) string {
	var parts []string
	if c > 0 {
		parts = append(parts, fmt.Sprintf("● %d critical", c))
	}
	if h > 0 {
		parts = append(parts, fmt.Sprintf("● %d high", h))
	}
	if m > 0 {
		parts = append(parts, fmt.Sprintf("● %d med", m))
	}
	if l > 0 {
		parts = append(parts, fmt.Sprintf("● %d low", l))
	}
	if i > 0 {
		parts = append(parts, fmt.Sprintf("● %d info", i))
	}
	return strings.Join(parts, "  ")
}

func buildSeverityColored(c, h, m, l, i int) string {
	var parts []string
	if c > 0 {
		parts = append(parts, criticalStyle.Sprintf("● %d critical", c))
	}
	if h > 0 {
		parts = append(parts, highStyle.Sprintf("● %d high", h))
	}
	if m > 0 {
		parts = append(parts, mediumStyle.Sprintf("● %d med", m))
	}
	if l > 0 {
		parts = append(parts, lowStyle.Sprintf("● %d low", l))
	}
	if i > 0 {
		parts = append(parts, fmt.Sprintf("● %d info", i))
	}
	return strings.Join(parts, "  ")
}

// ─── Footer lines ─────────────────────────────────────────────────────────────

// PrintReportReady prints the "→ Report at..." footer.
func PrintReportReady(url string, watch bool) {
	fmt.Printf("  → Report at %s\n", url)
	if watch {
		fmt.Printf("  → Watching for changes. Ctrl+C to stop.\n\n")
	} else {
		fmt.Printf("  → Ctrl+C to close\n\n")
	}
}

// PrintArrow prints an indented → status line.
func PrintArrow(msg string) {
	fmt.Printf("  → %s\n", msg)
}
