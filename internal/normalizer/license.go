package normalizer

import "strings"

// ClassifyLicense returns the risk level for an SPDX license identifier.
func ClassifyLicense(spdx string) LicenseRisk {
	if spdx == "" {
		return LicenseUnknown
	}
	upper := strings.ToUpper(spdx)

	// Copyleft — viral: your code may need to be open-sourced
	for _, prefix := range []string{
		"GPL-", "AGPL-", "GPL", "AGPL", "SSPL", "EUPL",
	} {
		if strings.HasPrefix(upper, prefix) {
			return LicenseCopyleft
		}
	}

	// Weak copyleft — OK if you don't modify the library itself
	for _, prefix := range []string{
		"LGPL-", "LGPL", "MPL-", "MPL", "EPL-", "EPL", "CDDL", "CPL",
	} {
		if strings.HasPrefix(upper, prefix) {
			return LicenseWeakCopyleft
		}
	}

	// Permissive — do whatever you want
	permissive := map[string]bool{
		"MIT": true, "ISC": true, "UNLICENSE": true, "UNLICENSED": true,
		"0BSD": true, "CC0-1.0": true, "WTFPL": true, "ZLIB": true,
		"BSL-1.0": true, "PSF-2.0": true, "PYTHON-2.0": true,
	}
	if permissive[upper] {
		return LicensePermissive
	}
	for _, prefix := range []string{
		"APACHE-", "APACHE", "BSD-", "BSD", "CC-BY-",
	} {
		if strings.HasPrefix(upper, prefix) {
			return LicensePermissive
		}
	}

	return LicenseUnknown
}

// MergeLicenses enriches a Package list with license data from Syft.
// The licenses map keys are "name@version".
func MergeLicenses(pkgs []Package, licenses map[string]string) {
	for i := range pkgs {
		key := pkgs[i].Name + "@" + pkgs[i].Version
		if lic, ok := licenses[key]; ok {
			pkgs[i].License = lic
			pkgs[i].LicenseRisk = ClassifyLicense(lic)
		} else if pkgs[i].License == "" {
			pkgs[i].LicenseRisk = LicenseUnknown
		}
	}
}
