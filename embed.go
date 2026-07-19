package trojan

import "embed"

//go:embed all:ui/dist
var UIAssets embed.FS

//go:embed all:dast-ui/dist
var DastUIAssets embed.FS
