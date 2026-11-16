package main

import (
	"fmt"
	"os"

	"github.com/fatih/color"

	"github.com/dev-zeph/trojan/internal/ai"
	"github.com/dev-zeph/trojan/internal/config"
	"github.com/dev-zeph/trojan/internal/scangate"
)

// requireScanAccess is the front door of a code scan: it needs a signed-in
// account with enough tokens to start. It exits the process (status 1) with a
// plain message when the scan may not run. Enforcement of what the AI check
// costs is server-side; this just stops a doomed run early.
func requireScanAccess() {
	token := ""
	if cfg, err := config.LoadConfig(); err == nil {
		token = cfg.AccessToken
	}
	res := scangate.Check(token, ai.FetchLicense)
	if res.Allowed {
		if res.Unverified {
			color.Yellow("  %s\n\n", res.Message)
		}
		return
	}
	fmt.Println()
	color.Yellow("  %s\n", res.Message)
	if res.Reason == scangate.ReasonSignedOut {
		fmt.Println("  Run `trojan login` to sign in.")
	}
	fmt.Println()
	os.Exit(1)
}
