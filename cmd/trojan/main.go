package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"

	trojan "github.com/dev-zeph/trojan"
	"github.com/dev-zeph/trojan/internal/ai"
	"github.com/dev-zeph/trojan/internal/ci"
	"github.com/dev-zeph/trojan/internal/config"
	"github.com/dev-zeph/trojan/internal/dast"
	"github.com/dev-zeph/trojan/internal/dast/agent"
	"github.com/dev-zeph/trojan/internal/hook"
	"github.com/dev-zeph/trojan/internal/mcpserver"
	"github.com/dev-zeph/trojan/internal/normalizer"
	"github.com/dev-zeph/trojan/internal/rag"
	"github.com/dev-zeph/trojan/internal/scanners"
	"github.com/dev-zeph/trojan/internal/server"
	"github.com/dev-zeph/trojan/internal/ui"
	"github.com/dev-zeph/trojan/internal/watcher"
)

var version = "0.0.1"

func main() {
	rootCmd := &cobra.Command{
		Use:   "trojan",
		Short: "A developer-first security CLI",
		Long:  "Trojan scans your codebase for vulnerabilities and opens a local web UI with plain-English explanations.",
	}

	rootCmd.AddCommand(versionCmd())
	rootCmd.AddCommand(scanCmd())
	rootCmd.AddCommand(dastCmd())
	rootCmd.AddCommand(ciCmd())
	rootCmd.AddCommand(initCmd())
	rootCmd.AddCommand(updateCmd())
	rootCmd.AddCommand(loginCmd())
	rootCmd.AddCommand(logoutCmd())
	rootCmd.AddCommand(proCmd())
	rootCmd.AddCommand(mcpCmd())
	rootCmd.AddCommand(hookCmd())
	rootCmd.AddCommand(verifyCmd())
	rootCmd.AddCommand(serveCmd())
	rootCmd.AddCommand(depsCmd())
	rootCmd.AddCommand(indexCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version number",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("trojan v%s\n", version)
		},
	}
}

func scanCmd() *cobra.Command {
	var preCommit bool
	var watch bool
	var desktop bool

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan the current project for vulnerabilities",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}

			// ----------------------------------------------------------------
			// --pre-commit mode: silent scan, exit 1 only on critical/high
			// ----------------------------------------------------------------
			if preCommit {
				if err := config.EnsureScanners(); err != nil {
					fmt.Fprintf(os.Stderr, "trojan: warning: could not install scanners: %s\n", err)
				}

				project := scanners.DetectProject(path)
				available := scanners.DefaultScanners()
				relevant := scanners.RelevantScanners(available, project)

				if len(relevant) == 0 {
					os.Exit(0)
				}

				findings := scanners.RunAll(path, relevant, nil)
				findings, _ = normalizer.Reduce(findings)

				var blocking []normalizer.Finding
				for _, f := range findings {
					if f.Severity == normalizer.SeverityCritical || f.Severity == normalizer.SeverityHigh {
						blocking = append(blocking, f)
					}
				}

				if len(blocking) == 0 {
					os.Exit(0)
				}

				fmt.Fprintln(os.Stderr, "")
				fmt.Fprintln(os.Stderr, "trojan: commit blocked — critical/high security findings detected:")
				fmt.Fprintln(os.Stderr, "")
				for _, f := range blocking {
					fmt.Fprintf(os.Stderr, "  [%s] %s\n", f.Severity, f.Title)
					if f.FilePath != "" {
						fmt.Fprintf(os.Stderr, "         %s", f.FilePath)
						if f.LineNumber > 0 {
							fmt.Fprintf(os.Stderr, ":%d", f.LineNumber)
						}
						fmt.Fprintln(os.Stderr)
					}
					if f.RuleID != "" {
						fmt.Fprintf(os.Stderr, "         rule: %s\n", f.RuleID)
					}
					fmt.Fprintln(os.Stderr)
				}
				fmt.Fprintln(os.Stderr, "Run `trojan scan` for a full interactive report.")
				fmt.Fprintln(os.Stderr, "Fix the issues above before committing.")
				os.Exit(1)
			}

			// ----------------------------------------------------------------
			// Normal interactive scan (with optional --watch)
			// ----------------------------------------------------------------

			// --watch requires Pro
			if watch {
				cfg, err := config.LoadConfig()
				if err != nil || !cfg.IsPro {
					color.Red("trojan scan --watch requires a Pro subscription.\n")
					fmt.Println("Visit https://trojancli.com/pricing to upgrade.")
					os.Exit(1)
				}
			}

			ui.PrintBanner(version)

			go config.NotifyIfOutdated(version)

			if err := config.EnsureScanners(); err != nil {
				color.Yellow("Warning: could not install scanners: %s\n", err)
			}

			project := scanners.DetectProject(path)
			available := scanners.DefaultScanners()
			relevant := scanners.RelevantScanners(available, project)

			if len(relevant) == 0 {
				color.Yellow("No scanners are installed. Run 'trojan init' to install them.\n")
				os.Exit(1)
			}

			// prevFindingIDs tracks finding IDs from the last scan so that
			// watch re-scans only synthesise AI for net-new findings. This
			// prevents repeated API calls for vulnerabilities that haven't
			// changed — the #1 cost driver in long watch sessions.
			prevFindingIDs := map[string]bool{}

			// runScan executes all scanners, synthesises AI for Pro users
			// (new findings only on re-scans), saves results, and returns
			// the ScanResult. Used for both the initial scan and every
			// re-scan triggered by --watch.
			runScan := func() (*normalizer.ScanResult, []normalizer.Finding) {
				ui.PrintScanHeader(path)

				// Build ordered name list and start the progress display.
				names := make([]string, len(relevant))
				for i, s := range relevant {
					names[i] = s.Name()
				}
				progress := ui.NewScanProgress(names)
				progress.Start()

				findings := scanners.RunAll(path, relevant, func(name string, done bool, count int, err error) {
					if done {
						progress.Update(name, count, err)
					}
				})

				// Deterministic noise reduction (A1 dedup + A3 path filter) —
				// the free floor beneath AI triage: drop non-shipping code and
				// collapse cross-scanner duplicates before anything else runs.
				findings, reduceStats := normalizer.Reduce(findings)
				if reduceStats.Any() {
					fmt.Printf("  → Filtered %d non-shipping, merged %d duplicate finding(s)\n",
						reduceStats.DroppedNonShipping, reduceStats.MergedDuplicates)
				}

				// Extract the dependency package list from Trivy (populated during Run()).
				var pkgs []normalizer.Package
				for _, s := range relevant {
					if t, ok := s.(*scanners.Trivy); ok {
						pkgs = t.Packages()
						break
					}
				}
				// Merge license data from Syft into the package list.
				for _, s := range relevant {
					if sy, ok := s.(*scanners.Syft); ok {
						if lics := sy.Licenses(); len(lics) > 0 {
							normalizer.MergeLicenses(pkgs, lics)
						}
						break
					}
				}

				// Enrich findings with compliance framework mappings.
				normalizer.EnrichCompliance(findings)

				// Severity counts for results box.
				counts := map[string]int{}
				for _, f := range findings {
					counts[string(f.Severity)]++
				}
				ui.PrintResultsBox(counts)

				isPro := false
				var accessToken string
				familiarity := 1
				aboutYou := ""
				if cfg, err := config.LoadConfig(); err == nil && cfg.AccessToken != "" {
					accessToken = cfg.AccessToken
					familiarity = cfg.Familiarity
					aboutYou = cfg.AboutYou
					if info, err := ai.FetchLicense(accessToken); err == nil {
						isPro = info.IsPro
					}
				}

				if isPro {
					// Enrich findings with project context before synthesis.
					// Framework and ProjectType are project-level — compute once.
					framework := ai.DetectFramework(path)
					projectType := ai.DetectProjectTypeName(path)
					for i := range findings {
						findings[i].Language = ai.DetectLanguage(findings[i].FilePath)
						findings[i].SurroundingCode = ai.ExtractEnclosingContext(findings[i].FilePath, findings[i].LineNumber)
						findings[i].Framework = framework
						findings[i].ProjectType = projectType
					}

					// Identify which findings are new since the last scan.
					// On the initial scan prevFindingIDs is empty so all
					// findings are synthesised. On re-scans only net-new
					// findings hit the API; existing ones are already cached
					// on disk at ~/.trojan/cache/ and skipped automatically.
					var toSynthesize []int
					for i, f := range findings {
						if !prevFindingIDs[f.ID] {
							toSynthesize = append(toSynthesize, i)
						}
					}

					if len(toSynthesize) > 0 {
						total := len(toSynthesize)
						const maxConcurrent = 8

						fmt.Printf("  → Synthesizing AI explanations for %d finding(s)...\n", total)

						var (
							progressMu sync.Mutex
							completed  int
						)

						sem := make(chan struct{}, maxConcurrent)
						var wg sync.WaitGroup

						for _, i := range toSynthesize {
							idx := i
							wg.Add(1)
							sem <- struct{}{}
							go func() {
								defer wg.Done()
								defer func() { <-sem }()

								s, err := ai.SynthesizeFinding(findings[idx], accessToken, familiarity, aboutYou)
								progressMu.Lock()
								defer progressMu.Unlock()
								if err == nil {
									findings[idx].Simply = s.Simply
									findings[idx].Actions = s.Actions
									findings[idx].Confidence = s.Confidence
									findings[idx].IsFalsePositive = s.IsFalsePositive
									findings[idx].FixDiff = s.FixDiff
								}
								completed++
								fmt.Printf("\r  → %d / %d complete", completed, total)
							}()
						}

						wg.Wait()
						fmt.Printf("\r  → %d / %d complete\n", total, total)
						ui.PrintArrow("Preparing actionable fix recommendations...")
						fmt.Println()
					}

					// Update the seen-findings set for the next re-scan.
					prevFindingIDs = make(map[string]bool, len(findings))
					for _, f := range findings {
						prevFindingIDs[f.ID] = true
					}

					// Pro: persist findings to disk.
					scanResult, err := normalizer.SaveScanResult(path, findings)
					if err != nil {
						color.Yellow("Warning: could not save scan results: %s\n", err)
						r := normalizer.NewScanResult(path, findings)
						r.Packages = pkgs
						r.Privacy = scanners.RunPrivacyScan(path)
						return r, findings
					}
					scanResult.Packages = pkgs
					scanResult.Privacy = scanners.RunPrivacyScan(path)
					return scanResult, findings
				}

				// Free tier: strip any cached AI content and keep everything
				// in memory only — nothing written to .trojan/scans/.
				for i := range findings {
					findings[i].Simply = ""
					findings[i].Actions = nil
				}
				r := normalizer.NewScanResult(path, findings)
				r.Packages = pkgs
				r.Privacy = scanners.RunPrivacyScan(path)
				return r, findings
			}

			// Initial scan
			scanResult, _ := runScan()
			if scanResult == nil {
				return
			}

			// Start local web server
			scanUI, _ := fs.Sub(trojan.UIAssets, "ui/dist")
			srv := server.New(scanResult, scanUI)
			url, err := srv.Start()
			if err != nil {
				color.Yellow("Warning: could not start UI server: %s\n", err)
				return
			}

			if watch {
				w, err := watcher.New(path, func() {
					fmt.Printf("  [%s] Change detected — rescanning...\n\n",
						time.Now().Format("15:04:05"))

					newResult, _ := runScan()
					if newResult != nil {
						srv.UpdateScan(newResult)
						color.Green("  → Report updated at %s\n\n", url)
					}
				})
				if err != nil {
					color.Yellow("Warning: could not start file watcher: %s\n", err)
				} else {
					defer w.Stop()
				}
			}

			if desktop {
				// Desktop mode: emit READY so Tauri navigates the webview to
				// the report URL. Print a blank line first to ensure any
				// in-progress animation output has been flushed, so the READY
				// signal lands on its own uncontaminated line.

				// Write cache for desktop re-serve
				cacheFile := desktopCachePath(path)
				if data, err := json.Marshal(scanResult); err == nil {
					if dir := filepath.Dir(cacheFile); os.MkdirAll(dir, 0755) == nil {
						os.WriteFile(cacheFile, data, 0644) //nolint:errcheck
						fmt.Printf("\nCACHE_PATH %s\n", cacheFile)
					}
				}

				fmt.Printf("\nREADY %s\n", url)
			} else {
				ui.PrintReportReady(url, watch)
				browser.OpenURL(url)
			}

			quit := make(chan os.Signal, 1)
			signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
			<-quit

			fmt.Println("\nServer closed.")
		},
	}

	cmd.Flags().BoolVar(&preCommit, "pre-commit", false, "Silent scan mode for git pre-commit hooks: exits 1 only on critical/high findings")
	cmd.Flags().BoolVar(&watch, "watch", false, "Re-scan on file changes and push updates to the open report")
	cmd.Flags().BoolVar(&desktop, "desktop", false, "Desktop app mode: skip browser, emit READY signal to stdout")
	cmd.Flags().MarkHidden("desktop") //nolint:errcheck // hide from CLI help — internal flag for Tauri sidecar

	return cmd
}

func dastCmd() *cobra.Command {
	var crawlDepth int
	var crawlTimeout int
	var desktop bool
	var agentic bool
	var tierStr, envStr string
	var acceptSideEffects bool
	var maxRunTokens int

	cmd := &cobra.Command{
		Use:   "dast <url>",
		Short: "Scan a running web server for runtime vulnerabilities (Pro)",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			targetURL := args[0]

			ui.PrintBanner(version)

			// ── Step 1: Pro gate — must be first, before any prompts ──────────────
			cfg, _ := config.LoadConfig()
			accessToken := ""
			dastFamiliarity := 1
			dastAboutYou := ""
			if cfg != nil {
				accessToken = cfg.AccessToken
				dastFamiliarity = cfg.Familiarity
				dastAboutYou = cfg.AboutYou
			}
			if accessToken == "" {
				printDastProMessage(targetURL)
				return
			}
			info, err := ai.FetchLicense(accessToken)
			if err != nil || !info.IsPro {
				printDastProMessage(targetURL)
				return
			}

			// ── Step 2: URL validation ─────────────────────────────────────────────
			if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
				color.Red("Error: URL must start with http:// or https://\n")
				os.Exit(1)
			}

			// ── Step 2.5: consent / ownership gate ─────────────────────────────────
			// No scan traffic reaches a non-local target until the user has proven
			// they control it. Enforced in desktop mode too — this is a legal gate,
			// not a nicety. localhost / private-IP targets bypass it (labelled).
			userEmail := ""
			if cfg != nil {
				userEmail = cfg.UserEmail
			}
			allowed, isLocalTarget, consentRec, gateDomain, gateErr := dast.GateStatus(targetURL, userEmail)
			if gateErr != nil {
				color.Red("\nError: %s\n", gateErr)
				os.Exit(1)
			}
			if isLocalTarget {
				color.New(color.Faint).Printf("  Local target (%s) — no ownership check required.\n", gateDomain)
			} else if allowed {
				color.Green("  Ownership verified for %s (%s).\n", gateDomain, consentRec.Method)
			} else {
				domain, token, _, mErr := dast.MintToken(targetURL, userEmail)
				if mErr != nil {
					color.Red("\nError preparing ownership check: %s\n", mErr)
					os.Exit(1)
				}
				if desktop {
					// Machine-readable signal for the desktop app (Phase 5 UI).
					fmt.Printf("CONSENT_REQUIRED %s %s\n", domain, token)
				}
				printConsentGate(targetURL, domain, token)
				os.Exit(1)
			}

			config.NotifyIfOutdated(version)

			// ── Agentic branch (Phase 4/5): the adaptive AI pen-tester ─────────────
			// Consent (Step 2.5) has already passed. Hand off to the agent loop,
			// which streams its run to the embedded "Penetration Testing" UI.
			if agentic {
				tier, terr := agent.ParseTier(tierStr)
				if terr != nil {
					color.Red("Error: %s\n", terr)
					os.Exit(1)
				}
				envv, eerr := agent.ParseEnvironment(envStr)
				if eerr != nil {
					color.Red("Error: %s\n", eerr)
					os.Exit(1)
				}
				runAgenticDast(agenticParams{
					targetURL:         targetURL,
					accessToken:       accessToken,
					tier:              tier,
					env:               envv,
					acceptSideEffects: acceptSideEffects,
					maxRunTokens:      maxRunTokens,
					desktop:           desktop,
					crawlDepth:        crawlDepth,
					crawlTimeout:      crawlTimeout,
				})
				return
			}

			fmt.Printf("\n  → Starting Trojan DAST (Pro)\n\n")

			// Cancel (desktop) / Ctrl+C aborts Nuclei immediately instead of
			// orphaning it against the target.
			installDastCancelHandler()

			// ── Step 3: Reachability check ─────────────────────────────────────────
			httpClient := &http.Client{Timeout: 5 * time.Second}
			if _, err := httpClient.Get(targetURL); err != nil { //nolint:noctx
				color.Red("\nCannot reach %s\n", targetURL)
				fmt.Println("Is your dev server running?")
				os.Exit(1)
			}

			// ── Step 4: confirmation flow (skipped in desktop mode) ────────────────
			if !desktop {
				reader := bufio.NewReader(os.Stdin)
				confirm := func(prompt string) {
					fmt.Printf("  %s (y/n): ", prompt)
					ans, _ := reader.ReadString('\n')
					if a := strings.TrimSpace(strings.ToLower(ans)); a != "y" && a != "yes" {
						fmt.Println("\nScan cancelled.")
						os.Exit(0)
					}
					fmt.Println()
				}

				color.Yellow("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

				fmt.Printf("  IMPORTANT: Only scan servers you own or have explicit written\n")
				fmt.Printf("  permission to test. Unauthorized scanning is illegal.\n\n")

				fmt.Printf("  Is %s the URL of your localhost instance?\n", targetURL)
				fmt.Println("  Testing against URLs you don't own is a crime")
				fmt.Println("  punishable by law.")
				fmt.Println()
				confirm("Confirm")

				fmt.Println("  DAST actively probes your server — it sends real attack")
				fmt.Println("  payloads to your local running app. It's always better")
				fmt.Println("  to find runtime vulnerabilities now before you push code.")
				fmt.Println()
				confirm("Understood")

				fmt.Println("  Your server logs will get spammy, that's expected.")
				fmt.Println("  Nuclei is firing 6,000+ templates plus AI-generated ones.")
				fmt.Println("  Don't panic.")
				fmt.Println()
				confirm("Got it")

				fmt.Println("  This normally takes 3 - 5 minutes. Take a break and")
				fmt.Println("  grab some tea, you deserve it. ☕")
				fmt.Println()
				confirm("Let's go")

				color.Yellow("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
			}

			// ── Step 5: Install Nuclei if missing ──────────────────────────────────
			if err := config.EnsureDastScanners(); err != nil {
				color.Yellow("Warning: could not install DAST scanners: %s\n", err)
			}

			// ── Step 6: Crawl ──────────────────────────────────────────────────────
			fmt.Printf("  → Crawling application (depth %d)...\n", crawlDepth)
			crawlResult := dast.Crawl(targetURL, crawlDepth, crawlTimeout)

			formCount := 0
			for _, e := range crawlResult.Endpoints {
				if e.Method == "POST" {
					formCount++
				}
			}
			endpointCount := len(crawlResult.Endpoints) - formCount
			fmt.Printf("  → Discovered %d endpoints and %d forms\n\n", endpointCount, formCount)

			// ── Step 7: AI template generation ────────────────────────────────────
			fmt.Printf("  → Generating AI attack templates...\n\n")

			tmpDir, err := os.MkdirTemp("", "trojan-dast-*")
			if err != nil {
				color.Yellow("Warning: could not create temp dir for templates: %s\n", err)
			}
			defer os.RemoveAll(tmpDir)

			templateReq := dast.TemplateRequest{
				TargetURL:    targetURL,
				Endpoints:    crawlResult.Endpoints,
				TechHints:    crawlResult.TechHints,
				MaxTemplates: 10,
			}
			templateResp, err := dast.GenerateTemplates(templateReq, accessToken)

			var nucleiScanner scanners.Nuclei
			if err != nil {
				if err.Error() == "rate_limit_exceeded" {
					color.Yellow("  Daily AI limit reached — running with standard templates only.\n\n")
				} else {
					color.Yellow("  Template generation failed (%s) — running with standard templates only.\n\n", err)
				}
			} else {
				if writeErr := dast.WriteTemplatesToDir(templateResp, tmpDir); writeErr == nil {
					fmt.Printf("  → Generated %d custom templates\n\n", len(templateResp.Templates))
					nucleiScanner = scanners.Nuclei{ExtraTemplateDirs: []string{tmpDir}}
				} else {
					fmt.Printf("  → Generated %d custom templates\n\n", len(templateResp.Templates))
					nucleiScanner = scanners.Nuclei{ExtraTemplateDirs: []string{tmpDir}}
				}
			}

			// ── Step 8: Nuclei scan ────────────────────────────────────────────────
			customCount := len(nucleiScanner.ExtraTemplateDirs)
			if customCount > 0 && templateResp != nil {
				fmt.Printf("  → Running Nuclei (6,618 standard + %d custom templates)...\n", len(templateResp.Templates))
			} else {
				fmt.Printf("  → Running Nuclei (6,618 standard templates)...\n")
			}
			fmt.Printf("  (First run will download templates — this may take a minute)\n\n")

			findings := scanners.RunDast(targetURL, []scanners.DastScanner{nucleiScanner}, func(name string, done bool, count int, err error) {
				if done && err != nil {
					color.Red("\n  [failed] %s: %s\n", name, err)
				}
			})

			fmt.Println()

			// ── Step 8.5: false-positive triage ────────────────────────────────────
			// Adversarially verify each finding against its own evidence so real
			// issues are separated from scanner noise (agentic DAST Phase 1).
			if len(findings) > 0 {
				fmt.Printf("  → Triaging %d finding(s) for false positives...\n", len(findings))
				if verdicts, terr := ai.TriageWithContext(findings, accessToken, loadRetriever(".", accessToken)); terr != nil {
					color.Yellow("  Triage skipped (%s)\n\n", terr)
				} else {
					for i := range findings {
						if v, ok := verdicts[findings[i].ID]; ok {
							findings[i].Verdict = v.Verdict
							findings[i].VerdictReason = v.Rationale
							findings[i].VerdictConfidence = v.Confidence
						}
					}
					fmt.Printf("      done\n\n")
				}
			}

			// ── Step 9: AI synthesis ───────────────────────────────────────────────
			if len(findings) > 0 {
				total := len(findings)
				const maxConcurrent = 8

				fmt.Printf("  → Synthesizing %d finding(s)...\n", total)

				var (
					progressMu sync.Mutex
					completed  int
				)

				sem := make(chan struct{}, maxConcurrent)
				var wg sync.WaitGroup

				for i := range findings {
					idx := i
					wg.Add(1)
					sem <- struct{}{}
					go func() {
						defer wg.Done()
						defer func() { <-sem }()

						s, serr := ai.SynthesizeFinding(findings[idx], accessToken, dastFamiliarity, dastAboutYou)
						progressMu.Lock()
						defer progressMu.Unlock()
						if serr == nil {
							findings[idx].Simply = s.Simply
							findings[idx].Actions = s.Actions
							findings[idx].Confidence = s.Confidence
							findings[idx].IsFalsePositive = s.IsFalsePositive
							findings[idx].FixDiff = s.FixDiff
						}
						completed++
						fmt.Printf("\r      %d / %d complete", completed, total)
					}()
				}

				wg.Wait()
				fmt.Printf("\r      %d / %d complete\n\n", total, total)
			}

			// ── Step 10: Results ───────────────────────────────────────────────────
			counts := map[normalizer.Severity]int{}
			for _, f := range findings {
				counts[f.Severity]++
			}
			fmt.Printf("  → DAST complete — %d findings (", len(findings))
			color.New(color.FgRed, color.Bold).Printf("%d critical  ", counts[normalizer.SeverityCritical])
			color.New(color.FgHiRed).Printf("%d high  ", counts[normalizer.SeverityHigh])
			color.New(color.FgYellow).Printf("%d medium  ", counts[normalizer.SeverityMedium])
			color.New(color.FgBlue).Printf("%d low", counts[normalizer.SeverityLow])
			fmt.Printf(")\n")

			// Persist under the cwd so MCP clients can read DAST findings too.
			scanResult := persistScan(targetURL, findings)

			dastUI, _ := fs.Sub(trojan.DastUIAssets, "dast-ui/dist")
			srv := server.New(scanResult, dastUI)
			reportURL, err := srv.Start()
			if err != nil {
				color.Yellow("Warning: could not start UI server: %s\n", err)
				return
			}

			if desktop {
				// Write cache for desktop re-serve
				cacheFile := desktopCachePath(targetURL)
				if data, err := json.Marshal(scanResult); err == nil {
					if dir := filepath.Dir(cacheFile); os.MkdirAll(dir, 0755) == nil {
						os.WriteFile(cacheFile, data, 0644) //nolint:errcheck
						fmt.Printf("\nCACHE_PATH %s\n", cacheFile)
					}
				}

				fmt.Printf("\nREADY %s\n", reportURL)
			} else {
				fmt.Printf("  → Report ready at %s\n", reportURL)
				fmt.Printf("  → Press Ctrl+C to close\n\n")
				browser.OpenURL(reportURL)
			}

			quit := make(chan os.Signal, 1)
			signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
			<-quit

			fmt.Println("\nServer closed.")
		},
	}

	cmd.Flags().IntVar(&crawlDepth, "crawl-depth", 2, "How many links deep to crawl")
	cmd.Flags().IntVar(&crawlTimeout, "timeout", 90, "Crawler timeout in seconds")
	cmd.Flags().BoolVar(&desktop, "desktop", false, "Desktop app mode: skip browser, emit READY signal to stdout")
	cmd.Flags().MarkHidden("desktop") //nolint:errcheck
	cmd.Flags().BoolVar(&agentic, "agentic", false, "Run the adaptive AI agent pen-tester instead of the one-shot scan (Pro)")
	cmd.Flags().StringVar(&tierStr, "tier", "passive", "Agentic scan intensity: passive | safe-active | aggressive")
	cmd.Flags().StringVar(&envStr, "env", "production", "Agentic target environment: production | staging")
	cmd.Flags().BoolVar(&acceptSideEffects, "accept-side-effects", false, "Acknowledge possible side effects (required for safe-active POST on production)")
	cmd.Flags().IntVar(&maxRunTokens, "max-run-tokens", agent.DefaultMaxRunTokens, "Cumulative token ceiling for the agentic run (0 = rely only on step/request/time caps)")
	cmd.AddCommand(dastVerifyCmd())
	return cmd
}

// dastVerifyCmd implements `trojan dast verify <url>` — the domain-ownership
// flow that unlocks scanning of a non-local target. With no --method it prints
// the token and the three placement options; with --method it checks that the
// token is live and persists a consent record on success.
func dastVerifyCmd() *cobra.Command {
	var method string

	cmd := &cobra.Command{
		Use:   "verify <url>",
		Short: "Prove you own a domain before pen-testing it (Pro)",
		Long: "Prove you control a domain before Trojan will scan it.\n\n" +
			"Run without --method to get your verification token and placement\n" +
			"instructions, then re-run with --method dns|file|meta to confirm.",
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			targetURL := args[0]
			ui.PrintBanner(version)

			// Pro gate — same as the scan path.
			cfg, _ := config.LoadConfig()
			accessToken := ""
			userEmail := ""
			if cfg != nil {
				accessToken = cfg.AccessToken
				userEmail = cfg.UserEmail
			}
			if accessToken == "" {
				printDastProMessage(targetURL)
				return
			}
			if info, err := ai.FetchLicense(accessToken); err != nil || !info.IsPro {
				printDastProMessage(targetURL)
				return
			}

			if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
				color.Red("Error: URL must start with http:// or https://\n")
				os.Exit(1)
			}

			// Already verified?
			if allowed, isLocal, rec, domain, gerr := dast.GateStatus(targetURL, userEmail); gerr == nil {
				if isLocal {
					color.New(color.Faint).Printf("\n  %s is a local target — no ownership check needed. Scan it directly.\n\n", domain)
					return
				}
				if allowed {
					color.Green("\n  Already verified: %s (%s, %s).\n\n", domain, rec.Method, rec.VerifiedAt.Format(time.RFC3339))
					return
				}
			}

			domain, token, isLocal, err := dast.MintToken(targetURL, userEmail)
			if err != nil {
				color.Red("\nError: %s\n", err)
				os.Exit(1)
			}
			if isLocal {
				color.New(color.Faint).Printf("\n  %s is a local target — no ownership check needed. Scan it directly.\n\n", domain)
				return
			}

			// No method → show instructions and the token.
			if method == "" {
				printConsentGate(targetURL, domain, token)
				return
			}

			// Run the requested check.
			m := dast.VerifyMethod(strings.ToLower(method))
			fmt.Printf("\n  Checking %s ownership via %s...\n", domain, m)
			rec, verr := dast.VerifyOwnership(targetURL, m, userEmail)
			if verr != nil {
				color.Red("\n  Verification failed: %s\n\n", verr)
				fmt.Printf("  Double-check the token is placed, then re-run:\n")
				fmt.Printf("    trojan dast verify %s --method %s\n\n", targetURL, m)
				os.Exit(1)
			}
			color.Green("\n  ✓ Verified ownership of %s via %s.\n", rec.Domain, rec.Method)
			fmt.Printf("  You can now run: trojan dast %s\n\n", targetURL)
		},
	}
	cmd.Flags().StringVar(&method, "method", "", "Check ownership now via: dns | file | meta")
	return cmd
}

// printConsentGate explains why a scan is blocked and how to prove ownership.
func printConsentGate(targetURL, domain, token string) {
	fmt.Println()
	color.Yellow("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	color.New(color.Bold).Printf("  Prove you own %s before scanning it.\n", domain)
	fmt.Println()
	fmt.Println("  Pen-testing a domain you don't control is illegal. Trojan")
	fmt.Println("  won't send a single probe until you verify ownership — the")
	fmt.Println("  same model as Google Search Console.")
	fmt.Println()
	color.New(color.Bold).Println("  Your verification token:")
	color.Cyan("    %s\n", token)
	fmt.Println()
	fmt.Println("  Place it using ANY ONE of these, then verify:")
	fmt.Println()
	color.New(color.Bold).Println("  1. DNS TXT record")
	fmt.Printf("     Add a TXT record on %s with value:\n", domain)
	color.Cyan("       %s%s\n", dast.TXTPrefix, token)
	fmt.Println()
	color.New(color.Bold).Println("  2. Well-known file")
	fmt.Printf("     Serve this file with the token as its body:\n")
	color.Cyan("       %s%s\n", strings.TrimSuffix(targetURL, "/"), dast.WellKnownPath)
	fmt.Println()
	color.New(color.Bold).Println("  3. Homepage meta tag")
	fmt.Printf("     Add to the <head> of your homepage:\n")
	color.Cyan("       <meta name=\"%s\" content=\"%s\">\n", dast.MetaName, token)
	fmt.Println()
	color.New(color.Bold).Println("  Then verify (pick the method you used):")
	fmt.Printf("    trojan dast verify %s --method dns\n", targetURL)
	fmt.Printf("    trojan dast verify %s --method file\n", targetURL)
	fmt.Printf("    trojan dast verify %s --method meta\n", targetURL)
	fmt.Println()
	color.Yellow("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
}

// agenticParams bundles everything runAgenticDast needs.
type agenticParams struct {
	targetURL         string
	accessToken       string
	tier              agent.Tier
	env               agent.Environment
	acceptSideEffects bool
	maxRunTokens      int
	desktop           bool
	crawlDepth        int
	crawlTimeout      int
}

// runAgenticDast drives the adaptive AI pen-test (docs/agentic-dast.md Phase 4/5).
// It crawls, runs the deterministic Nuclei pre-pass for breadth (locked decision
// #3), starts the embedded "Penetration Testing" UI early so the run streams
// live, drives the agent loop, then merges + triages the findings.
// installDastCancelHandler makes SIGINT/SIGTERM (sent by the desktop's Cancel
// button, or Ctrl+C) force-kill any in-flight Nuclei scan and exit immediately,
// so cancelling aborts the scan instead of orphaning Nuclei against the target.
func installDastCancelHandler() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		scanners.TerminateDastScans()
		os.Exit(130)
	}()
}

func runAgenticDast(p agenticParams) {
	installDastCancelHandler()
	fmt.Printf("\n  → Starting Trojan agentic pen-test (Pro)\n\n")

	// Reachability.
	httpClient := &http.Client{Timeout: 5 * time.Second}
	if _, err := httpClient.Get(p.targetURL); err != nil { //nolint:noctx
		color.Red("\nCannot reach %s\n", p.targetURL)
		fmt.Println("Is the server running?")
		os.Exit(1)
	}

	// Crawl.
	fmt.Printf("  → Crawling application (depth %d)...\n", p.crawlDepth)
	crawlResult := dast.Crawl(p.targetURL, p.crawlDepth, p.crawlTimeout)
	fmt.Printf("  → Discovered %d endpoint(s)\n\n", len(crawlResult.Endpoints))

	// Deterministic Nuclei pre-pass for breadth (zero tokens).
	if err := config.EnsureDastScanners(); err != nil {
		color.Yellow("Warning: could not install DAST scanners: %s\n", err)
	}
	fmt.Printf("  → Running Nuclei baseline...\n")
	baseline := scanners.RunDast(p.targetURL, []scanners.DastScanner{scanners.Nuclei{}}, func(_ string, _ bool, _ int, _ error) {})
	fmt.Printf("  → Baseline: %d finding(s)\n\n", len(baseline))

	// Start the UI server early so the run view can watch the agent live.
	scanResult := normalizer.NewScanResult(p.targetURL, baseline)
	dastUI, _ := fs.Sub(trojan.DastUIAssets, "dast-ui/dist")
	srv := server.New(scanResult, dastUI)
	reportURL, err := srv.Start()
	if err != nil {
		color.Yellow("Warning: could not start UI server: %s\n", err)
		return
	}
	srv.ResetAgenticRun()

	// Deterministic cache path for this target. We emit CACHE_PATH *before*
	// READY (the desktop's await_ready only captures it pre-READY), seed the
	// file with the baseline so it exists, and overwrite it with the full
	// results on completion. This lets "recent targets" re-serve the finished
	// report instead of starting a brand-new scan.
	cacheFile := desktopCachePath(p.targetURL)
	if p.desktop {
		writeDesktopCache(cacheFile, scanResult)
		fmt.Printf("\nCACHE_PATH %s\n", cacheFile)
		fmt.Printf("\nREADY %s\n", reportURL)
	} else {
		fmt.Printf("  → Live run at %s\n", reportURL)
		fmt.Printf("  → Press Ctrl+C to close\n\n")
		browser.OpenURL(reportURL)
	}

	// Drive the loop, streaming every action to the UI and the terminal.
	srv.BroadcastAgentEvent(server.AgentEvent{Type: "run", Status: "running"})
	res, rerr := agent.RunAgentic(context.Background(), agent.Config{
		TargetURL:         p.targetURL,
		AccessToken:       p.accessToken,
		Crawl:             crawlResult,
		Tier:              p.tier,
		Env:               p.env,
		AcceptSideEffects: p.acceptSideEffects,
		MaxRunTokens:      p.maxRunTokens,
		Task:              buildAgenticTask(p.targetURL, p.tier, p.env, crawlResult, baseline),
		OnEvent: func(e agent.Event) {
			srv.BroadcastAgentEvent(server.AgentEvent{Type: string(e.Type), Step: e.Step, Tool: e.Tool, Detail: e.Detail})
			printAgentEvent(e)
		},
	})

	if rerr != nil {
		srv.BroadcastAgentEvent(server.AgentEvent{Type: "run", Status: "error", Detail: rerr.Error()})
		color.Red("\n  Agentic run failed: %s\n", rerr)
	} else {
		// Merge the agent's evidence-anchored candidates with the Nuclei baseline,
		// then run everything through adversarial triage (Phase 1).
		all := append(baseline, agenticFindingsFromCandidates(res.Findings)...) //nolint:gocritic
		if len(all) > 0 {
			if verdicts, terr := ai.TriageWithContext(all, p.accessToken, loadRetriever(".", p.accessToken)); terr == nil {
				for i := range all {
					if v, ok := verdicts[all[i].ID]; ok {
						all[i].Verdict = v.Verdict
						all[i].VerdictReason = v.Rationale
						all[i].VerdictConfidence = v.Confidence
					}
				}
			}
		}

		// AI synthesis — plain-English explanation + fix actions per finding, the
		// same pass the one-shot scan runs. Without it, Simply/Actions are empty
		// and the report shows the Pro upsell even to logged-in Pro users.
		synthesizeFindings(all, p.accessToken)

		// Persist under the cwd so `trojan mcp` (run from the same project) can
		// read these DAST findings; ProjectPath keeps the scanned URL for display.
		scan := persistScan(p.targetURL, all)
		srv.UpdateScan(scan)
		// Overwrite the desktop cache with the finished results so re-opening
		// this target from "recent" shows the full report (not a new scan).
		if p.desktop {
			writeDesktopCache(cacheFile, scan)
		}
		srv.BroadcastAgentEvent(server.AgentEvent{Type: "run", Status: "complete", Detail: res.Summary})
		fmt.Printf("\n  → Agentic pen-test complete — %d candidate finding(s); %s\n", len(res.Findings), stopLabel(res))
	}

	// Keep the server alive until cancelled/closed — installDastCancelHandler
	// (installed at the top) handles SIGINT/SIGTERM and exits the process.
	select {}
}

// buildAgenticTask composes the seed message: the goal, the run's tier +
// allowed methods (so the agent doesn't waste turns on rejected probes), and a
// summary of the crawl + Nuclei baseline.
func buildAgenticTask(url string, tier agent.Tier, env agent.Environment, crawl dast.CrawlResult, baseline []normalizer.Finding) string {
	methods := "GET, HEAD, OPTIONS"
	if tier >= agent.TierSafeActive {
		methods += ", POST (non-destructive confirmation only)"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Penetration-test %s.\n", url)
	fmt.Fprintf(&b, "Environment: %s. Scan-intensity tier: %s. Allowed HTTP methods: %s.\n", env, tier, methods)
	fmt.Fprintf(&b, "The crawler found %d endpoint(s) and %d technology hint(s) — call get_crawl_map for the full map.\n", len(crawl.Endpoints), len(crawl.TechHints))
	if len(baseline) > 0 {
		fmt.Fprintf(&b, "A Nuclei baseline scan already flagged %d issue(s) for breadth; spend your reasoning on the multi-step and business-logic flaws those templates can't express.\n", len(baseline))
	}
	b.WriteString("Review the crawl map first, then probe adaptively. Record findings with note_finding anchored on the evidence you observe, and call finish when you have tested the hypotheses worth testing.")
	return b.String()
}

// agenticFindingsFromCandidates maps the agent's evidence-anchored candidates
// into normalized findings so they flow through triage and the report UI.
func agenticFindingsFromCandidates(cs []agent.Candidate) []normalizer.Finding {
	out := make([]normalizer.Finding, 0, len(cs))
	for i, c := range cs {
		h := sha256.Sum256([]byte(c.Title + "|" + c.URL + "|" + fmt.Sprint(i)))
		out = append(out, normalizer.Finding{
			ID:          "agentic-" + fmt.Sprintf("%x", h)[:12],
			Scanner:     "agentic-dast",
			Category:    "dast",
			Severity:    parseAgentSeverity(c.Severity),
			Title:       c.Title,
			RawMessage:  c.Rationale,
			FilePath:    c.URL,
			CodeSnippet: c.Evidence,
			RuleID:      "agentic",
			Status:      normalizer.StatusOpen,
		})
	}
	return out
}

// synthesizeFindings populates Simply/Actions/etc. on each finding via the AI
// synthesis edge function (Pro). Mirrors the one-shot scan's Step 9. Familiarity
// and profile come from local config so explanations match the user's level.
func synthesizeFindings(findings []normalizer.Finding, accessToken string) {
	if len(findings) == 0 {
		return
	}
	fam, about := 1, ""
	if cfg, _ := config.LoadConfig(); cfg != nil {
		fam, about = cfg.Familiarity, cfg.AboutYou
	}

	fmt.Printf("  → Synthesizing %d finding(s)...\n", len(findings))
	const maxConcurrent = 8
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := range findings {
		idx := i
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			s, serr := ai.SynthesizeFinding(findings[idx], accessToken, fam, about)
			if serr != nil {
				return
			}
			mu.Lock()
			findings[idx].Simply = s.Simply
			findings[idx].Actions = s.Actions
			findings[idx].Confidence = s.Confidence
			findings[idx].IsFalsePositive = s.IsFalsePositive
			findings[idx].FixDiff = s.FixDiff
			mu.Unlock()
		}()
	}
	wg.Wait()
}

// persistScan writes the findings under the cwd's .trojan/scans/ (so MCP can read
// them) with the scanned URL as the display path, falling back to in-memory if
// the write fails.
func persistScan(targetURL string, findings []normalizer.Finding) *normalizer.ScanResult {
	cwd, err := os.Getwd()
	if err != nil {
		return normalizer.NewScanResult(targetURL, findings)
	}
	if scan, serr := normalizer.SaveScanResultAt(cwd, targetURL, findings); serr == nil {
		return scan
	}
	return normalizer.NewScanResult(targetURL, findings)
}

func parseAgentSeverity(s string) normalizer.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return normalizer.SeverityCritical
	case "high":
		return normalizer.SeverityHigh
	case "medium":
		return normalizer.SeverityMedium
	case "low":
		return normalizer.SeverityLow
	default:
		return normalizer.SeverityInfo
	}
}

func printAgentEvent(e agent.Event) {
	switch e.Type {
	case agent.EventStep:
		fmt.Printf("  [step %d]\n", e.Step)
	case agent.EventText:
		fmt.Printf("    · %s\n", truncateLine(e.Detail, 100))
	case agent.EventToolUse:
		fmt.Printf("    → %s\n", e.Tool)
	case agent.EventToolResult:
		fmt.Printf("      %s\n", truncateLine(e.Detail, 100))
	case agent.EventFinding:
		color.Green("    ✓ finding: %s\n", e.Detail)
	case agent.EventStopped:
		color.Yellow("  stopped: %s\n", e.Detail)
	case agent.EventFinish:
		if e.Detail != "" {
			fmt.Printf("  finished: %s\n", truncateLine(e.Detail, 120))
		}
	}
}

func stopLabel(res *agent.RunResult) string {
	if res.EndedBy == agent.EventStopped {
		return "stopped: " + string(res.StopReason)
	}
	return "agent finished"
}

func truncateLine(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// writeDesktopCache serializes a scan result to the desktop cache file so the
// desktop app can re-serve it later via `trojan serve` (no re-scan). Best-effort.
func writeDesktopCache(path string, scan *normalizer.ScanResult) {
	data, err := json.Marshal(scan)
	if err != nil {
		return
	}
	if dir := filepath.Dir(path); os.MkdirAll(dir, 0755) != nil {
		return
	}
	os.WriteFile(path, data, 0644) //nolint:errcheck
}

// desktopCachePath returns the path for the desktop cache file for a given target.
// It uses the first 16 hex chars of the SHA-256 of the target as the filename.
func desktopCachePath(target string) string {
	h := sha256.Sum256([]byte(target))
	name := fmt.Sprintf("%x", h)[:16] + ".json"
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".trojan", "desktop-cache", name)
}

// serveCmd reads a previously-written cache file and starts a fresh HTTP server
// so the desktop app can re-open old scan results without re-running scanners.
func serveCmd() *cobra.Command {
	var desktop bool

	cmd := &cobra.Command{
		Use:    "serve <cache-file>",
		Short:  "Serve a cached scan result (desktop re-open)",
		Args:   cobra.ExactArgs(1),
		Hidden: true,
		Run: func(cmd *cobra.Command, args []string) {
			cacheFile := args[0]

			data, err := os.ReadFile(cacheFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "trojan serve: cannot read cache file: %s\n", err)
				os.Exit(1)
			}

			var result normalizer.ScanResult
			if err := json.Unmarshal(data, &result); err != nil {
				fmt.Fprintf(os.Stderr, "trojan serve: invalid cache file: %s\n", err)
				os.Exit(1)
			}

			// Choose the correct UI bundle based on the target type.
			var scanUI fs.FS
			if strings.HasPrefix(result.ProjectPath, "http") {
				scanUI, _ = fs.Sub(trojan.DastUIAssets, "dast-ui/dist")
			} else {
				scanUI, _ = fs.Sub(trojan.UIAssets, "ui/dist")
			}

			srv := server.New(&result, scanUI)
			url, err := srv.Start()
			if err != nil {
				fmt.Fprintf(os.Stderr, "trojan serve: could not start server: %s\n", err)
				os.Exit(1)
			}

			if desktop {
				fmt.Printf("\nREADY %s\n", url)
			} else {
				fmt.Printf("Serving cached scan at %s\nPress Ctrl+C to stop.\n", url)
			}

			quit := make(chan os.Signal, 1)
			signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
			<-quit
			fmt.Println("\nServer closed.")
		},
	}

	cmd.Flags().BoolVar(&desktop, "desktop", false, "Desktop app mode: emit READY signal to stdout")
	cmd.Flags().MarkHidden("desktop") //nolint:errcheck

	return cmd
}

// depsCmd is a hidden, desktop-only command that runs Trivy only and serves
// the resulting package list so the Dependencies sidebar can be populated
// quickly without running all scanners.
func depsCmd() *cobra.Command {
	var desktop bool

	cmd := &cobra.Command{
		Use:    "deps [path]",
		Short:  "Scan dependencies only (Trivy)",
		Args:   cobra.MaximumNArgs(1),
		Hidden: true,
		Run: func(cmd *cobra.Command, args []string) {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}

			if err := config.EnsureScanners(); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not install scanners: %s\n", err)
			}

			t := &scanners.Trivy{}
			if !t.IsAvailable() {
				fmt.Fprintln(os.Stderr, "trivy not found: run 'trojan init' to install it")
				os.Exit(1)
			}

			findings, err := t.Run(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "trivy failed: %s\n", err)
				os.Exit(1)
			}

			result := normalizer.NewScanResult(path, findings)
			result.Packages = t.Packages()

			scanUI, _ := fs.Sub(trojan.UIAssets, "ui/dist")
			srv := server.New(result, scanUI)
			url, startErr := srv.Start()
			if startErr != nil {
				fmt.Fprintf(os.Stderr, "could not start UI server: %s\n", startErr)
				os.Exit(1)
			}

			if desktop {
				cacheFile := desktopCachePath("deps::" + path)
				if data, err := json.Marshal(result); err == nil {
					if dir := filepath.Dir(cacheFile); os.MkdirAll(dir, 0755) == nil {
						os.WriteFile(cacheFile, data, 0644) //nolint:errcheck
						fmt.Printf("\nCACHE_PATH %s\n", cacheFile)
					}
				}
				fmt.Printf("\nREADY %s\n", url)
			} else {
				fmt.Printf("Dependency report at %s\n", url)
			}

			quit := make(chan os.Signal, 1)
			signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
			<-quit
		},
	}

	cmd.Flags().BoolVar(&desktop, "desktop", false, "Desktop app mode: emit READY signal to stdout")
	cmd.Flags().MarkHidden("desktop") //nolint:errcheck

	return cmd
}

func printDastProMessage(targetURL string) {
	fmt.Println()
	fmt.Println("  trojan dast is a Pro feature.")
	fmt.Println()
	fmt.Printf("  Pro DAST: smart crawling of %s + custom AI attack templates + synthesis.\n", targetURL)
	fmt.Println("  Upgrade at trojancli.com/pricing to unlock it.")
	fmt.Println()
}


func loginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Log in to Trojan (always fetches a fresh token)",
		Run: func(cmd *cobra.Command, args []string) {
			ui.PrintBanner(version)
			// Always re-authenticate — never skip — so plan changes are picked up immediately.
			if err := config.Login(); err != nil {
				color.Red("Login failed: %s\n", err)
				os.Exit(1)
			}
			cfg, _ := config.LoadConfig()
			color.Green("Logged in as %s\n", cfg.UserEmail)
			// ForceRefreshLicense validates pro status server-side (includes org seat membership)
			info, err := config.ForceRefreshLicense()
			if err == nil && info.IsPro {
				color.Green("Plan: Pro\n")
			} else {
				fmt.Println("Plan: Free. Visit https://trojancli.com/pricing to upgrade.")
			}
			fmt.Println("Run `trojan scan` to start scanning.")
		},
	}
}

func logoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Log out and clear saved credentials",
		Run: func(cmd *cobra.Command, args []string) {
			if err := config.Logout(); err != nil {
				color.Red("Error: %s\n", err)
				os.Exit(1)
			}
			fmt.Println("Logged out.")
		},
	}
}

func updateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Check for a newer version of Trojan",
		Run: func(cmd *cobra.Command, args []string) {
			ui.PrintBanner(version)
			if err := config.RunUpdate(version); err != nil {
				color.Red("Error: %s\n", err)
				os.Exit(1)
			}
		},
	}
}

func indexCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "index [path]",
		Short: "Build a local code index for AI-assisted triage (Pro)",
		Long: `Chunk this project's source into a local semantic index that gives AI triage
richer context — the custom sanitizer, guard, or caller a single finding can't
see on its own — so false positives are caught and real issues confirmed.

Privacy: building the index sends source-code chunks to Trojan's embedding
service to be turned into vectors. The vectors and the index are stored locally
under .trojan/index/ and never leave your machine. Nothing is indexed unless you
run this command; re-run it after significant changes (only changed files are
re-embedded).`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}

			cfg, err := config.LoadConfig()
			if err != nil || cfg.AccessToken == "" {
				color.Yellow("Log in first: `trojan login`\n")
				os.Exit(1)
			}
			if info, lerr := ai.FetchLicense(cfg.AccessToken); lerr != nil || !info.IsPro {
				color.Yellow("Indexing is a Pro feature. Visit https://trojancli.com/pricing to upgrade.\n")
				os.Exit(1)
			}

			files, err := rag.WalkSource(path)
			if err != nil {
				color.Red("Could not enumerate source files: %s\n", err)
				os.Exit(1)
			}
			if len(files) == 0 {
				fmt.Println("No source files found to index.")
				return
			}

			// Disclosure + explicit opt-in (docs §4 privacy boundary).
			fmt.Printf("About to index %d source file(s) under %s.\n", len(files), path)
			color.Yellow("Code chunks will be sent to Trojan's embedding service; the resulting vectors are stored locally in .trojan/index/.\n")
			if !yes {
				fmt.Print("Proceed? [y/N] ")
				line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
				if strings.ToLower(strings.TrimSpace(line)) != "y" {
					fmt.Println("Aborted — nothing was indexed.")
					return
				}
			}

			ix := &rag.Indexer{Embedder: ai.NewEmbedder(cfg.AccessToken)}
			fmt.Printf("Indexing %d file(s)...\n", len(files))
			stats, err := ix.IndexProject(path, files)
			if err != nil {
				color.Red("Index failed: %s\n", err)
				os.Exit(1)
			}
			color.Green("✓ Indexed %d file(s), %d chunk(s) — %d unchanged, %d pruned.\n",
				stats.FilesIndexed, stats.ChunksAdded, stats.FilesSkipped, stats.FilesPruned)
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip the confirmation prompt")
	return cmd
}

// ragRetriever adapts *rag.Retriever to ai.ContextRetriever so the ai package
// (which owns triage) needs no import of rag. main is the composition root.
type ragRetriever struct{ r *rag.Retriever }

func (a ragRetriever) Retrieve(query string, k int) ([]ai.RetrievedChunk, error) {
	res, err := a.r.Retrieve(query, k)
	if err != nil {
		return nil, err
	}
	out := make([]ai.RetrievedChunk, len(res))
	for i, c := range res {
		out[i] = ai.RetrievedChunk{
			FilePath:  c.Chunk.FilePath,
			StartLine: c.Chunk.StartLine,
			EndLine:   c.Chunk.EndLine,
			Text:      c.Chunk.Text,
		}
	}
	return out, nil
}

// loadRetriever returns a context retriever backed by the project's code index,
// or nil when no index exists — triage then degrades gracefully to a plain pass.
func loadRetriever(projectPath, accessToken string) ai.ContextRetriever {
	if !rag.ProjectHasIndex(projectPath) {
		return nil
	}
	r, err := rag.NewRetriever(projectPath, ai.NewEmbedder(accessToken))
	if err != nil {
		return nil
	}
	return ragRetriever{r}
}

func proCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "pro",
		Short: "Check your Pro subscription status",
		Run: func(cmd *cobra.Command, args []string) {
			if !config.IsLoggedIn() {
				color.Yellow("Not logged in. Run `trojan login` first.\n")
				os.Exit(1)
			}
			cfg, err := config.LoadConfig()
			if err != nil {
				color.Red("Error: %s\n", err)
				os.Exit(1)
			}
			status := config.SubscriptionStatusFromToken(cfg.AccessToken)
			if status == "pro" || status == "team" {
				color.Green("✓ You're the pro. (%s)\n", status)
				fmt.Println("AI explanations are active. Run `trojan scan` to use them.")
			} else {
				color.Yellow("Free plan. Visit https://trojancli.com/pricing to upgrade.\n")
				fmt.Println("After upgrading, log out and back in: `trojan login`")
			}
		},
	}
}

func mcpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp [path]",
		Short: "MCP server for AI editor integrations",
		Long:  `Start the Trojan MCP server over stdio, or install it into your AI editors.`,
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}
			if err := mcpserver.Serve(path); err != nil {
				color.Red("MCP server error: %s\n", err)
				os.Exit(1)
			}
		},
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "install",
		Short: "Auto-configure Claude Code, Cursor, and Codex CLI to use Trojan MCP",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Detecting AI editors...")
			fmt.Println()
			if err := mcpserver.Install(); err != nil {
				color.Red("Error: %s\n", err)
				os.Exit(1)
			}
		},
	})

	return cmd
}

func initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Install scanners and set up Trojan for this project",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ui.PrintBanner(version)
			path := "."
			if len(args) > 0 {
				path = args[0]
			}
			if err := config.RunInit(path); err != nil {
				color.Red("Error: %s\n", err)
				os.Exit(1)
			}
		},
	}
}

func hookCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Manage Trojan git hooks",
		Long:  "Install or uninstall the Trojan pre-commit hook in a git repository.",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "install [path]",
		Short: "Install the Trojan pre-commit hook",
		Long: `Install a pre-commit hook that runs 'trojan scan --pre-commit' before each commit.

The hook blocks commits that have Critical or High severity findings.
If a pre-commit hook already exists and was not installed by Trojan, the
command will warn you and leave the existing hook untouched.`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}
			if err := hook.Install(path); err != nil {
				color.Red("Error: %s\n", err)
				os.Exit(1)
			}
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "uninstall [path]",
		Short: "Remove the Trojan pre-commit hook",
		Long: `Remove the pre-commit hook previously installed by Trojan.

If the hook was not installed by Trojan (no '# trojan' marker), the command
will refuse to remove it to avoid accidentally deleting custom hooks.`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}
			if err := hook.Uninstall(path); err != nil {
				color.Red("Error: %s\n", err)
				os.Exit(1)
			}
		},
	})

	return cmd
}

func verifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Verify the integrity and authenticity of this Trojan binary",
		Long: `Verify confirms that the running Trojan binary:

  1. Matches the SHA256 hash published with its GitHub release.
  2. Was signed by Trojan Software Solutions (GPG signature verified
     against the public key embedded in this binary).

No gpg binary is required — verification runs entirely in Go.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Verifying Trojan v%s...\n\n", version)

			result, err := config.VerifyBinary(version)
			if err != nil {
				color.Red("Verification error: %s\n", err)
				os.Exit(1)
			}

			// Print binary info
			fmt.Printf("  Binary   %s\n", result.BinaryPath)
			fmt.Printf("  Platform %s\n", result.Platform)
			fmt.Printf("  SHA256   %s\n\n", result.BinaryHash)

			// Hash check
			if result.ExpectedHash == "" {
				color.Yellow("  Hash     could not retrieve expected hash from release\n")
			} else if result.HashMatch {
				color.Green("  Hash     ✓ matches release (v%s)\n", result.Version)
			} else {
				color.Red("  Hash     ✗ MISMATCH\n")
				color.Red("           expected: %s\n", result.ExpectedHash)
				color.Red("           got:      %s\n", result.BinaryHash)
			}

			// Signature check
			if result.SignatureError != nil {
				color.Yellow("  Sig      could not verify: %s\n", result.SignatureError)
			} else if result.SignatureValid {
				color.Green("  Sig      ✓ valid GPG signature from Trojan Software Solutions\n")
			} else {
				color.Red("  Sig      ✗ INVALID — do not use this binary\n")
			}

			fmt.Println()

			// Overall verdict
			if result.HashMatch && result.SignatureValid {
				color.Green("✓ Binary is authentic and unmodified.\n")
			} else if !result.HashMatch {
				color.Red("✗ Hash mismatch — binary has been modified or corrupted.\n")
				color.Red("  Reinstall from https://trojancli.com or via: brew reinstall trojan\n")
				os.Exit(1)
			} else {
				color.Yellow("~ Hash verified but signature check was inconclusive.\n")
				color.Yellow("  See https://trojancli.com/security for the public key.\n")
			}
		},
	}
}

func ciCmd() *cobra.Command {
	var outputFile string
	var severityThreshold string

	cmd := &cobra.Command{
		Use:   "ci [path]",
		Short: "Run all scanners and output SARIF 2.1.0 for CI pipelines",
		Long: `Run all security scanners silently and emit SARIF 2.1.0 JSON to stdout (or --output file).
Summary lines are written to stderr so SARIF output stays clean.
Exits 1 if findings at or above --severity threshold are detected.`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}

			// Auto-install missing scanners (quiet — errors go to stderr).
			if err := config.EnsureScanners(); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not install scanners: %s\n", err)
			}

			// Detect project and pick relevant scanners.
			project := scanners.DetectProject(path)
			available := scanners.DefaultScanners()
			relevant := scanners.RelevantScanners(available, project)

			if len(relevant) == 0 {
				fmt.Fprintln(os.Stderr, "No scanners are installed. Run 'trojan init' to install them.")
				os.Exit(1)
			}

			fmt.Fprintf(os.Stderr, "Scanning %s with %d scanner(s)...\n", path, len(relevant))

			// Run all scanners in parallel — no spinners, no UI.
			findings := scanners.RunAll(path, relevant, nil)
			findings, reduceStats := normalizer.Reduce(findings)
			if reduceStats.Any() {
				fmt.Fprintf(os.Stderr,
					"Filtered %d non-shipping finding(s), merged %d cross-scanner duplicate(s)\n",
					reduceStats.DroppedNonShipping, reduceStats.MergedDuplicates)
			}

			// Tally by severity.
			counts := map[normalizer.Severity]int{}
			for _, f := range findings {
				counts[f.Severity]++
			}

			fmt.Fprintf(os.Stderr,
				"Found %d findings (%d critical, %d high, %d medium, %d low)\n",
				len(findings),
				counts[normalizer.SeverityCritical],
				counts[normalizer.SeverityHigh],
				counts[normalizer.SeverityMedium],
				counts[normalizer.SeverityLow],
			)

			// Determine failure threshold.
			threshold := normalizer.Severity(severityThreshold)
			switch threshold {
			case normalizer.SeverityCritical,
				normalizer.SeverityHigh,
				normalizer.SeverityMedium,
				normalizer.SeverityLow,
				normalizer.SeverityInfo:
				// valid
			default:
				fmt.Fprintf(os.Stderr, "Warning: unknown severity %q, defaulting to 'high'\n", severityThreshold)
				threshold = normalizer.SeverityHigh
			}

			// Check whether any findings breach the threshold.
			failing := false
			for _, f := range findings {
				if severityAtOrAbove(f.Severity, threshold) {
					failing = true
					break
				}
			}

			// Serialize SARIF.
			sarifBytes, err := ci.MarshalSARIF(findings, version)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error building SARIF output: %s\n", err)
				os.Exit(2)
			}

			// Write SARIF to file or stdout.
			if outputFile != "" {
				if err := os.WriteFile(outputFile, sarifBytes, 0644); err != nil {
					fmt.Fprintf(os.Stderr, "Error writing SARIF to %s: %s\n", outputFile, err)
					os.Exit(2)
				}
				fmt.Fprintf(os.Stderr, "SARIF written to %s\n", outputFile)
			} else {
				fmt.Println(string(sarifBytes))
			}

			// Print result and exit with appropriate code.
			if failing {
				fmt.Fprintf(os.Stderr, "→ Failing: critical/high findings detected\n")
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "→ Clean: no critical or high findings\n")
		},
	}

	cmd.Flags().StringVar(&outputFile, "output", "", "Write SARIF output to this file instead of stdout")
	cmd.Flags().StringVar(&severityThreshold, "severity", "high", "Minimum severity that triggers a non-zero exit (critical, high, medium, low, info)")

	return cmd
}

// severityAtOrAbove returns true if s is at or above the given threshold in
// terms of criticality (critical > high > medium > low > info).
func severityAtOrAbove(s, threshold normalizer.Severity) bool {
	order := map[normalizer.Severity]int{
		normalizer.SeverityInfo:     0,
		normalizer.SeverityLow:      1,
		normalizer.SeverityMedium:   2,
		normalizer.SeverityHigh:     3,
		normalizer.SeverityCritical: 4,
	}
	return order[s] >= order[threshold]
}
