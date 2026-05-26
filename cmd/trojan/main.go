package main

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"

	trojan "github.com/dev-zeph/trojan"
	"github.com/dev-zeph/trojan/internal/ai"
	"github.com/dev-zeph/trojan/internal/ci"
	"github.com/dev-zeph/trojan/internal/config"
	"github.com/dev-zeph/trojan/internal/hook"
	"github.com/dev-zeph/trojan/internal/mcpserver"
	"github.com/dev-zeph/trojan/internal/normalizer"
	"github.com/dev-zeph/trojan/internal/scanners"
	"github.com/dev-zeph/trojan/internal/server"
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
	rootCmd.AddCommand(ciCmd())
	rootCmd.AddCommand(initCmd())
	rootCmd.AddCommand(updateCmd())
	rootCmd.AddCommand(loginCmd())
	rootCmd.AddCommand(logoutCmd())
	rootCmd.AddCommand(proCmd())
	rootCmd.AddCommand(mcpCmd())
	rootCmd.AddCommand(hookCmd())
	rootCmd.AddCommand(verifyCmd())

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
				if err != nil || !config.IsProFromToken(cfg.AccessToken) {
					color.Red("trojan scan --watch requires a Pro subscription.\n")
					fmt.Println("Visit https://trojancli.com/pricing to upgrade.")
					os.Exit(1)
				}
			}

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
				fmt.Printf("Scanning %s with %d scanner(s)...\n\n", path, len(relevant))

				spins := map[string]*spinner.Spinner{}
				var spinnerMu sync.Mutex

				for _, s := range relevant {
					sp := spinner.New(spinner.CharSets[14], 80*time.Millisecond)
					sp.Suffix = fmt.Sprintf("  [running] %s (%s)", s.Name(), s.Category())
					sp.Start()
					spins[s.Name()] = sp
				}

				findings := scanners.RunAll(path, relevant, func(name string, done bool, err error) {
					spinnerMu.Lock()
					defer spinnerMu.Unlock()
					sp, ok := spins[name]
					if !ok {
						return
					}
					if done {
						sp.Stop()
						if err != nil {
							color.Red("  [failed] %s: %s\n", name, err)
						} else {
							color.Green("  [done]   %s\n", name)
						}
					}
				})

				fmt.Println()
				printFindings(findings)

				isPro := false
				var accessToken string
				if cfg, err := config.LoadConfig(); err == nil {
					accessToken = cfg.AccessToken
					isPro = config.IsProFromToken(accessToken)
				}

				if isPro {
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

						fmt.Printf("Generating simplified summaries for %d finding(s)...\n", total)

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

								s, err := ai.SynthesizeFinding(findings[idx], accessToken)
								progressMu.Lock()
								defer progressMu.Unlock()
								if err == nil {
									findings[idx].Simply = s.Simply
									findings[idx].Actions = s.Actions
								}
								completed++
								fmt.Printf("\r  %d / %d complete", completed, total)
							}()
						}

						wg.Wait()
						fmt.Printf("\r  %d / %d complete\n", total, total)
						fmt.Println("Preparing actionable fix recommendations...")
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
						return normalizer.NewScanResult(path, findings), findings
					}
					return scanResult, findings
				}

				// Free tier: strip any cached AI content and keep everything
				// in memory only — nothing written to .trojan/scans/.
				for i := range findings {
					findings[i].Simply = ""
					findings[i].Actions = nil
				}
				return normalizer.NewScanResult(path, findings), findings
			}

			// Initial scan
			scanResult, _ := runScan()
			if scanResult == nil {
				return
			}

			// Start local web server
			srv := server.New(scanResult, trojan.UIAssets)
			url, err := srv.Start()
			if err != nil {
				color.Yellow("Warning: could not start UI server: %s\n", err)
				return
			}

			fmt.Printf("\n→ Report ready at %s\n", url)

			if watch {
				fmt.Printf("→ Watching for file changes. Press Ctrl+C to stop.\n\n")

				w, err := watcher.New(path, func() {
					fmt.Printf("\n[%s] Change detected — rescanning...\n\n",
						time.Now().Format("15:04:05"))

					newResult, _ := runScan()
					if newResult != nil {
						srv.UpdateScan(newResult)
						color.Green("→ Report updated at %s\n\n", url)
					}
				})
				if err != nil {
					color.Yellow("Warning: could not start file watcher: %s\n", err)
				} else {
					defer w.Stop()
				}
			} else {
				fmt.Printf("→ Press Ctrl+C to close\n\n")
			}

			browser.OpenURL(url)

			quit := make(chan os.Signal, 1)
			signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
			<-quit

			fmt.Println("\nServer closed.")
		},
	}

	cmd.Flags().BoolVar(&preCommit, "pre-commit", false, "Silent scan mode for git pre-commit hooks: exits 1 only on critical/high findings")
	cmd.Flags().BoolVar(&watch, "watch", false, "Re-scan on file changes and push updates to the open report")

	return cmd
}

func printFindings(findings []normalizer.Finding) {
	if len(findings) == 0 {
		color.Green("No findings. Your code looks clean!\n")
		return
	}

	counts := map[normalizer.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	fmt.Printf("Found %d issue(s):  ", len(findings))
	color.New(color.FgRed, color.Bold).Printf("%d critical  ", counts[normalizer.SeverityCritical])
	color.New(color.FgHiRed).Printf("%d high  ", counts[normalizer.SeverityHigh])
	color.New(color.FgYellow).Printf("%d medium  ", counts[normalizer.SeverityMedium])
	color.New(color.FgBlue).Printf("%d low\n", counts[normalizer.SeverityLow])
	fmt.Printf("→ Open the report for details.\n\n")
}

func loginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Log in to Trojan (always fetches a fresh token)",
		Run: func(cmd *cobra.Command, args []string) {
			// Always re-authenticate — never skip — so plan changes are picked up immediately.
			if err := config.Login(); err != nil {
				color.Red("Login failed: %s\n", err)
				os.Exit(1)
			}
			cfg, _ := config.LoadConfig()
			color.Green("Logged in as %s\n", cfg.UserEmail)
			status := config.SubscriptionStatusFromToken(cfg.AccessToken)
			if status == "pro" || status == "team" {
				color.Green("Plan: %s\n", status)
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
			if err := config.RunUpdate(version); err != nil {
				color.Red("Error: %s\n", err)
				os.Exit(1)
			}
		},
	}
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
			fmt.Println("Detecting AI editors...\n")
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
