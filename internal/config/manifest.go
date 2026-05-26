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
	Name      string                   // human-readable name e.g. "Trivy"
	Binary    string                   // installed binary filename e.g. "trivy"
	Version   string                   // pinned version string
	Platforms map[string]PlatformAsset // keyed by "darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64"
}

// Scanners is the pinned manifest. Update versions + SHA256s here when cutting a new Trojan release.
// To recompute SHA256 for any archive:   shasum -a 256 <file>   (macOS / Linux)
var Scanners = []ScannerManifest{
	{
		Name:    "Trivy",
		Binary:  "trivy",
		Version: "0.70.0",
		Platforms: map[string]PlatformAsset{
			"linux/amd64": {
				URL:             "https://github.com/aquasecurity/trivy/releases/download/v0.70.0/trivy_0.70.0_Linux-64bit.tar.gz",
				SHA256:          "8b4376d5d6befe5c24d503f10ff136d9e0c49f9127a4279fd110b727929a5aa9",
				Archive:         ArchiveTarGz,
				BinaryInArchive: "trivy",
			},
			"linux/arm64": {
				URL:             "https://github.com/aquasecurity/trivy/releases/download/v0.70.0/trivy_0.70.0_Linux-ARM64.tar.gz",
				SHA256:          "2f6bb988b553a1bbac6bdd1ce890f5e412439564e17522b88a4541b4f364fc8d",
				Archive:         ArchiveTarGz,
				BinaryInArchive: "trivy",
			},
			"darwin/amd64": {
				URL:             "https://github.com/aquasecurity/trivy/releases/download/v0.70.0/trivy_0.70.0_macOS-64bit.tar.gz",
				SHA256:          "52d531452b19e7593da29366007d02a810e1e0080d02f9cf6a1afb46c35aaa93",
				Archive:         ArchiveTarGz,
				BinaryInArchive: "trivy",
			},
			"darwin/arm64": {
				URL:             "https://github.com/aquasecurity/trivy/releases/download/v0.70.0/trivy_0.70.0_macOS-ARM64.tar.gz",
				SHA256:          "68e543c51dcc96e1c344053a4fde9660cf602c25565d9f09dc17dd41e13b838a",
				Archive:         ArchiveTarGz,
				BinaryInArchive: "trivy",
			},
		},
	},
	{
		Name:    "Semgrep",
		Binary:  "semgrep",
		Version: "1.89.0",
		// Semgrep does not ship standalone binaries — installed via pip into ~/.trojan/venv/.
		// The same pip entry is used for all platforms.
		Platforms: map[string]PlatformAsset{
			"linux/amd64":  {Archive: ArchivePip, PipPackage: "semgrep==1.89.0"},
			"linux/arm64":  {Archive: ArchivePip, PipPackage: "semgrep==1.89.0"},
			"darwin/amd64": {Archive: ArchivePip, PipPackage: "semgrep==1.89.0"},
			"darwin/arm64": {Archive: ArchivePip, PipPackage: "semgrep==1.89.0"},
		},
	},
	{
		Name:    "Gitleaks",
		Binary:  "gitleaks",
		Version: "8.30.1",
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
		},
	},
	{
		Name:    "Checkov",
		Binary:  "checkov",
		Version: "3.2.529",
		// No native darwin/arm64 build — uses darwin/amd64 via Rosetta on Apple Silicon.
		Platforms: map[string]PlatformAsset{
			"linux/amd64": {
				URL:             "https://github.com/bridgecrewio/checkov/releases/download/3.2.529/checkov_linux_X86_64.zip",
				SHA256:          "84b837a42d647711d066b7acf89e6ccadbb15b3977a6f7cde552d860faec01b7",
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
				URL:             "https://github.com/bridgecrewio/checkov/releases/download/3.2.529/checkov_darwin_X86_64.zip",
				SHA256:          "e9b1f27e297f029dc52295d940c94225dc333252b21ae05f86a6bd7ab8599d85",
				Archive:         ArchiveZip,
				BinaryInArchive: "dist/checkov",
			},
			"darwin/arm64": {
				// No native arm64 build — Rosetta runs x86_64 transparently on Apple Silicon
				URL:             "https://github.com/bridgecrewio/checkov/releases/download/3.2.529/checkov_darwin_X86_64.zip",
				SHA256:          "e9b1f27e297f029dc52295d940c94225dc333252b21ae05f86a6bd7ab8599d85",
				Archive:         ArchiveZip,
				BinaryInArchive: "dist/checkov",
			},
		},
	},
	{
		Name:    "Syft",
		Binary:  "syft",
		Version: "1.44.0",
		Platforms: map[string]PlatformAsset{
			"linux/amd64": {
				URL:             "https://github.com/anchore/syft/releases/download/v1.44.0/syft_1.44.0_linux_amd64.tar.gz",
				SHA256:          "0e91737aee2b5baf1d255b959630194a302335d848ff97bb07921eb6205b5f5a",
				Archive:         ArchiveTarGz,
				BinaryInArchive: "syft",
			},
			"linux/arm64": {
				URL:             "https://github.com/anchore/syft/releases/download/v1.44.0/syft_1.44.0_linux_arm64.tar.gz",
				SHA256:          "6f6cdcdc695721d91ce756e3b5bc3e3416599c464101f5e32e9c3f33054ee6d9",
				Archive:         ArchiveTarGz,
				BinaryInArchive: "syft",
			},
			"darwin/amd64": {
				URL:             "https://github.com/anchore/syft/releases/download/v1.44.0/syft_1.44.0_darwin_amd64.tar.gz",
				SHA256:          "c40ece5407927327f94f35901727dbc604b46857e04f04ec94a310845fb71bde",
				Archive:         ArchiveTarGz,
				BinaryInArchive: "syft",
			},
			"darwin/arm64": {
				URL:             "https://github.com/anchore/syft/releases/download/v1.44.0/syft_1.44.0_darwin_arm64.tar.gz",
				SHA256:          "24e4d34078ae81da7c82539616f0ccac3e226cf4f74a38ce6fb3463619e50a55",
				Archive:         ArchiveTarGz,
				BinaryInArchive: "syft",
			},
		},
	},
}
