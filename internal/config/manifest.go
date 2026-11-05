package config

// ArchiveType describes how a scanner release asset is packaged.
type ArchiveType string

const (
	ArchiveTarGz  ArchiveType = "tar.gz"  // .tar.gz — extract binary from inside
	ArchiveZip    ArchiveType = "zip"     // .zip    — extract binary from inside
	ArchiveDirect ArchiveType = "direct"  // raw binary, no archive
	ArchivePip    ArchiveType = "pip"     // pip package installed into ~/.trojan/venv/
)

// PlatformAsset describes the download for one OS/arch combination.
type PlatformAsset struct {
	URL             string      // full download URL (unused for ArchivePip)
	SHA256          string      // expected SHA256 of the downloaded archive
	Archive         ArchiveType // how the asset is packaged
	BinaryInArchive string      // path to the binary inside the archive
	PipPackage      string      // "name==version" for ArchivePip installs
}

// ScannerManifest describes everything needed to install one scanner.
type ScannerManifest struct {
	Name       string                   // human-readable name e.g. "Trivy"
	Binary     string                   // installed binary filename e.g. "trivy"
	Version    string                   // pinned version string
	GitHubRepo string                   // "owner/repo" of the releases (reference only; installs use the pinned assets)
	TagPrefix  string                   // prefix in release tags, e.g. "v" for tags like "v0.70.0"
	Platforms  map[string]PlatformAsset // keyed by "darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64"
	// PipFallback is a second pinned "name==version" for pip scanners, tried
	// when the main pin can't install on the user's Python (macOS ships 3.9).
	PipFallback string
	// InstallMB is roughly the disk space the installed scanner takes, used to
	// make sure an install can't fill the user's disk.
	InstallMB int
}

// Scanners is the pinned manifest for SAST/SCA scanners installed by `trojan init`.
// To recompute SHA256 for any archive:   shasum -a 256 <file>   (macOS / Linux)
var Scanners = []ScannerManifest{
	{
		Name:       "Trivy",
		InstallMB:  200,
		Binary:     "trivy",
		Version:    "0.76.1",
		GitHubRepo: "aquasecurity/trivy",
		TagPrefix:  "v",
		Platforms: map[string]PlatformAsset{
			"linux/amd64": {
				URL:             "https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_Linux-64bit.tar.gz",
				SHA256:          "c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0",
				Archive:         ArchiveTarGz,
				BinaryInArchive: "trivy",
			},
			"linux/arm64": {
				URL:             "https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_Linux-ARM64.tar.gz",
				SHA256:          "e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f",
				Archive:         ArchiveTarGz,
				BinaryInArchive: "trivy",
			},
			"darwin/amd64": {
				URL:             "https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_macOS-64bit.tar.gz",
				SHA256:          "7aa762eacd582052d053b62dcf972a1ab058abe39a57ccae234ed8894945b6b7",
				Archive:         ArchiveTarGz,
				BinaryInArchive: "trivy",
			},
			"darwin/arm64": {
				URL:             "https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_macOS-ARM64.tar.gz",
				SHA256:          "11a9b6cd2752011b54f01ea4bd0dbfa9f0c41dc6538d5a3f9d23955f471bf4e5",
				Archive:         ArchiveTarGz,
				BinaryInArchive: "trivy",
			},
			"windows/amd64": {
				URL:             "https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_windows-64bit.zip",
				SHA256:          "1051f49cb22d5284f43425f72aad9cda63ca12ceb92e7caa06903490c82dc9bf",
				Archive:         ArchiveZip,
				BinaryInArchive: "trivy.exe",
			},
		},
	},
	{
		Name:       "Semgrep",
		InstallMB:  300,
		Binary:     "semgrep",
		Version:    "1.157.0",
		GitHubRepo: "semgrep/semgrep",
		TagPrefix:  "v",
		// Semgrep does not ship standalone binaries — installed via pip into ~/.trojan/venv/.
		// The same pip entry is used for all platforms. Semgrep after 1.136.0
		// needs Python 3.10+, but macOS ships 3.9, so 1.136.0 is the fallback
		// rather than letting the installer reach for Homebrew.
		PipFallback: "semgrep==1.136.0",
		Platforms: map[string]PlatformAsset{
			"linux/amd64":   {Archive: ArchivePip, PipPackage: "semgrep==1.157.0"},
			"linux/arm64":   {Archive: ArchivePip, PipPackage: "semgrep==1.157.0"},
			"darwin/amd64":  {Archive: ArchivePip, PipPackage: "semgrep==1.157.0"},
			"darwin/arm64":  {Archive: ArchivePip, PipPackage: "semgrep==1.157.0"},
			"windows/amd64": {Archive: ArchivePip, PipPackage: "semgrep==1.157.0"},
		},
	},
	{
		Name:       "Gitleaks",
		InstallMB:  30,
		Binary:     "gitleaks",
		Version:    "8.30.1",
		GitHubRepo: "gitleaks/gitleaks",
		TagPrefix:  "v",
		Platforms: map[string]PlatformAsset{
			"linux/amd64": {
				URL:             "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz",
				SHA256:          "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
				Archive:         ArchiveTarGz,
				BinaryInArchive: "gitleaks",
			},
			"linux/arm64": {
				URL:             "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_arm64.tar.gz",
				SHA256:          "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
				Archive:         ArchiveTarGz,
				BinaryInArchive: "gitleaks",
			},
			"darwin/amd64": {
				URL:             "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_darwin_x64.tar.gz",
				SHA256:          "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709",
				Archive:         ArchiveTarGz,
				BinaryInArchive: "gitleaks",
			},
			"darwin/arm64": {
				URL:             "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_darwin_arm64.tar.gz",
				SHA256:          "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
				Archive:         ArchiveTarGz,
				BinaryInArchive: "gitleaks",
			},
			"windows/amd64": {
				URL:             "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_windows_x64.zip",
				SHA256:          "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e",
				Archive:         ArchiveZip,
				BinaryInArchive: "gitleaks.exe",
			},
		},
	},
	{
		Name:       "Checkov",
		InstallMB:  400,
		Binary:     "checkov",
		Version:    "3.4.3",
		GitHubRepo: "bridgecrewio/checkov",
		TagPrefix:  "",
		// No native darwin/arm64 binary: Apple Silicon installs the pip package.
		// No linux/arm64 build after 3.2.529, so that platform stays on 3.2.529.
		Platforms: map[string]PlatformAsset{
			"linux/amd64": {
				URL:             "https://github.com/bridgecrewio/checkov/releases/download/3.4.3/checkov_linux_X86_64.zip",
				SHA256:          "f4f183b7fa57351f62400321f72bf6e24958670909d389f0f1973faa784a0135",
				Archive:         ArchiveZip,
				BinaryInArchive: "dist/checkov",
			},
			"linux/arm64": {
				URL:             "https://github.com/bridgecrewio/checkov/releases/download/3.2.529/checkov_linux_arm64.zip",
				SHA256:          "fff55b064eadfc14ce35da9b9744dedf82fb50c25447076149480ad92c06a6a9",
				Archive:         ArchiveZip,
				BinaryInArchive: "dist/checkov",
			},
			"darwin/amd64": {
				URL:             "https://github.com/bridgecrewio/checkov/releases/download/3.4.3/checkov_darwin_X86_64.zip",
				SHA256:          "2a048a05a93abdafb94011eeb1bd3cc21fdec16cc3d6978340a724f88e38d2b2",
				Archive:         ArchiveZip,
				BinaryInArchive: "dist/checkov",
			},
			"darwin/arm64": {
				// No native arm64 build of the binary (only x86_64, which needs
				// Rosetta, missing on new Apple Silicon Macs and being phased out).
				// The pip package runs natively in Trojan's own Python instead.
				Archive:    ArchivePip,
				PipPackage: "checkov==3.4.3",
			},
			"windows/amd64": {
				URL:             "https://github.com/bridgecrewio/checkov/releases/download/3.4.3/checkov_windows_X86_64.zip",
				SHA256:          "f9a6ec2a4f2c6ca3e24248d6244fc967f734dbd9f10c40755d7d5c9db960246b",
				Archive:         ArchiveZip,
				BinaryInArchive: "dist/checkov.exe",
			},
		},
	},
	{
		Name:       "Syft",
		InstallMB:  100,
		Binary:     "syft",
		Version:    "1.56.0",
		GitHubRepo: "anchore/syft",
		TagPrefix:  "v",
		Platforms: map[string]PlatformAsset{
			"linux/amd64": {
				URL:             "https://github.com/anchore/syft/releases/download/v1.56.0/syft_1.56.0_linux_amd64.tar.gz",
				SHA256:          "1c2493cfcf52d3367d6cb25780d9190c111c2219c34c820574c43e8bae15c528",
				Archive:         ArchiveTarGz,
				BinaryInArchive: "syft",
			},
			"linux/arm64": {
				URL:             "https://github.com/anchore/syft/releases/download/v1.56.0/syft_1.56.0_linux_arm64.tar.gz",
				SHA256:          "ace61b9397ae28189c674ae332d67a8074dafd71e87724dfb8b22412d8253bb5",
				Archive:         ArchiveTarGz,
				BinaryInArchive: "syft",
			},
			"darwin/amd64": {
				URL:             "https://github.com/anchore/syft/releases/download/v1.56.0/syft_1.56.0_darwin_amd64.tar.gz",
				SHA256:          "ff37fb20e8d072e193cb659ecb932994ba2add772cbf86909c368fb95a630c50",
				Archive:         ArchiveTarGz,
				BinaryInArchive: "syft",
			},
			"darwin/arm64": {
				URL:             "https://github.com/anchore/syft/releases/download/v1.56.0/syft_1.56.0_darwin_arm64.tar.gz",
				SHA256:          "c19b97a8c175ac7bd8105b8c8240ce740bf078333b12cc62ea49002c1b33e6e0",
				Archive:         ArchiveTarGz,
				BinaryInArchive: "syft",
			},
			"windows/amd64": {
				URL:             "https://github.com/anchore/syft/releases/download/v1.56.0/syft_1.56.0_windows_amd64.zip",
				SHA256:          "c4cd2846dc0128e29a947bc6f56e1e5ef01707275b0e58590fbe48105198661d",
				Archive:         ArchiveZip,
				BinaryInArchive: "syft.exe",
			},
		},
	},
	{
		Name:       "Bearer",
		InstallMB:  150,
		Binary:     "bearer",
		Version:    "2.1.3",
		GitHubRepo: "Bearer/bearer",
		TagPrefix:  "v",
		Platforms: map[string]PlatformAsset{
			"linux/amd64": {
				URL:             "https://github.com/Bearer/bearer/releases/download/v2.1.3/bearer_2.1.3_linux_amd64.tar.gz",
				SHA256:          "974d4ad7bb71bc578675684d444e345e8fbad91c85557aac035406ef5cc04c68",
				Archive:         ArchiveTarGz,
				BinaryInArchive: "bearer",
			},
			"linux/arm64": {
				URL:             "https://github.com/Bearer/bearer/releases/download/v2.1.3/bearer_2.1.3_linux_arm64.tar.gz",
				SHA256:          "93e340650311d4129689a25e7063dd146bcda2e33d22adf15ffba5fc8b112260",
				Archive:         ArchiveTarGz,
				BinaryInArchive: "bearer",
			},
			"darwin/amd64": {
				URL:             "https://github.com/Bearer/bearer/releases/download/v2.1.3/bearer_2.1.3_darwin_amd64.tar.gz",
				SHA256:          "d16d67f906c22f0c25f08c380704ce0fd4fc231c1b00b10bc0a73a69bbfab5a0",
				Archive:         ArchiveTarGz,
				BinaryInArchive: "bearer",
			},
			"darwin/arm64": {
				URL:             "https://github.com/Bearer/bearer/releases/download/v2.1.3/bearer_2.1.3_darwin_arm64.tar.gz",
				SHA256:          "927ce356022a15dcf9a7a61fefe33335d62bbec2014fc63e7114f348aeba4f7d",
				Archive:         ArchiveTarGz,
				BinaryInArchive: "bearer",
			},
		},
	},
}

// DastScanners is the pinned manifest for DAST scanners.
// These are installed lazily by `trojan dast` rather than eagerly by `trojan init`.
var DastScanners = []ScannerManifest{
	{
		Name:       "Nuclei",
		InstallMB:  120,
		Binary:     "nuclei",
		Version:    "3.8.0",
		GitHubRepo: "projectdiscovery/nuclei",
		TagPrefix:  "v",
		Platforms: map[string]PlatformAsset{
			"linux/amd64": {
				URL:             "https://github.com/projectdiscovery/nuclei/releases/download/v3.8.0/nuclei_3.8.0_linux_amd64.zip",
				SHA256:          "cd4ea43c88b50af8ab96eb6ad3fb4debd8e9d51efaff4d4c2d99106041578943",
				Archive:         ArchiveZip,
				BinaryInArchive: "nuclei",
			},
			"linux/arm64": {
				URL:             "https://github.com/projectdiscovery/nuclei/releases/download/v3.8.0/nuclei_3.8.0_linux_arm64.zip",
				SHA256:          "deb622901acda6bbc6ffe771b98b2d41276667cc5dca6ce403b6ae331ccba64e",
				Archive:         ArchiveZip,
				BinaryInArchive: "nuclei",
			},
			"darwin/amd64": {
				URL:             "https://github.com/projectdiscovery/nuclei/releases/download/v3.8.0/nuclei_3.8.0_macOS_amd64.zip",
				SHA256:          "b8ad7476b4698561f9956b276643c9eeee2391e4c8caf88580ee2c1aef0160f0",
				Archive:         ArchiveZip,
				BinaryInArchive: "nuclei",
			},
			"darwin/arm64": {
				URL:             "https://github.com/projectdiscovery/nuclei/releases/download/v3.8.0/nuclei_3.8.0_macOS_arm64.zip",
				SHA256:          "872b49984a014eb6bf9022eb95889c9e5935900624d06880b1d856914606e80f",
				Archive:         ArchiveZip,
				BinaryInArchive: "nuclei",
			},
			"windows/amd64": {
				URL:             "https://github.com/projectdiscovery/nuclei/releases/download/v3.8.0/nuclei_3.8.0_windows_amd64.zip",
				SHA256:          "5378cee06b67f6aa78d4e34ed717c18f6d1d8d8d44a089b46d91afcc76f8ec1d",
				Archive:         ArchiveZip,
				BinaryInArchive: "nuclei.exe",
			},
		},
	},
}
