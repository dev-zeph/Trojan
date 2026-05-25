# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in Trojan, **do not open a public GitHub issue**.

Email **security@trojan.dev** with:
- A description of the vulnerability
- Steps to reproduce
- Potential impact

We aim to respond within 48 hours and will keep you informed throughout the fix process. We will credit you in the release notes unless you prefer otherwise.

---

## Release Integrity

Every Trojan release is signed, attested, and reproducibly built. You can verify any installed binary independently.

### How releases are secured

**GPG signing**
The checksums file (`trojan_VERSION_checksums.txt`) and binary checksums file (`trojan_VERSION_binary_checksums.txt`) for every release are signed with our GPG key. The public key is embedded in the binary itself, so `trojan verify` requires no external tooling.

**SLSA provenance**
Every release is attested via GitHub's SLSA provenance action, published to the public Sigstore transparency log. This creates a verifiable chain from source code → GitHub Actions build → released binary.

**Reproducible builds**
Trojan is built with `CGO_ENABLED=0` and deterministic ldflags. You can compile from source and verify the hash matches the release.

**Config file permissions**
`~/.trojan/config.json` (which holds your auth token) is written with `0600` permissions — owner read/write only.

---

### Verify your installation

Run this at any time to confirm your binary is authentic:

```sh
trojan verify
```

This checks:
1. The SHA256 of the running binary against the hash published with its release
2. The GPG signature on the checksums file against our embedded public key

### Verify with SLSA (requires GitHub CLI)

```sh
gh attestation verify trojan_VERSION_darwin_arm64.tar.gz \
  --repo dev-zeph/Trojan
```

### Verify manually

```sh
# Download the checksums file and signature for your version
curl -fsSL https://github.com/dev-zeph/Trojan/releases/download/vVERSION/trojan_VERSION_checksums.txt -o checksums.txt
curl -fsSL https://github.com/dev-zeph/Trojan/releases/download/vVERSION/trojan_VERSION_checksums.txt.sig -o checksums.txt.sig

# Verify the signature (requires gpg)
gpg --verify checksums.txt.sig checksums.txt

# Verify the archive hash
sha256sum --check --ignore-missing checksums.txt
```

### Build from source

```sh
git clone https://github.com/dev-zeph/Trojan
cd Trojan
cd ui && npm ci && npm run build && cd ..
CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=SOURCE" ./cmd/trojan/
```

The resulting binary hash should match the binary in our releases for the same version.

---

## Our public GPG key

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBGoUfTMBEADf7XMzKvYGB2tobF3WJmV1+R2OverQpMGjfeLIWchVyDJDQjyn
j/C8wVh6QsKNf2pP12+LlbdF4YKJfk4MFfWFda/uiS0SUytwJk0Cf1qNpKNI1niD
xuM/M2MKWXPQBtC7FLbOttj4dhtUjJfYUl1QlCpR1KD7UaLTDXOgqTFTvpa6HlPl
llV+VyZCXpSOvpT7mSlII68gK7b1EZiWCW6/Jk8zWYWlTiQzwn/pcwK+zramNIqH
Omjt7DdwpkxnmwPAo+zJvcuwkuNqx0bDgtFNqFJRY+xg5hTQ6Q4hG03yzeta2WZk
8dXoh1CfWVFySZW/9QjJ/t/2VibrO8lU0Gm1agq9aZijVLs+sZm5Qn/f+TND5Us1
ueAbO9h5Iqo80w5nZrU9vQrVKN4kFOGq5l/SMZY2v3U2L59wrxUTqfK/Uitc+30K
e2xNoMD3cZE0oTghmOwbkXbXZegP7vWc9kt9iD/kuPn5O6MJILopYN11dhiLlLV/
C4TmUVMoj1WcyE7rTsUW72P0CnKtf8+46ll99xHjb92RMhXE9dsSjuGRW9vw6GVm
VGgwSiMnpPH62m+HSlmkLCwKyiarHSFLSlUa7aPbMTOdFohQNwMRiDwadEQfurGO
1dm6VqZpvgeldh9WCXIs5Ra2Mql7ggXIN2NBgF+IKstjRqb8VmxaGalcYQARAQAB
tDlDaGl6dWx1IFplcGhhbmlhaCAoU2lnbmF0dXJlIGtleSkgPHplcGhjaGl6dWx1
QGdtYWlsLmNvbT6JAm0EEwEIAFcWIQQhUePSmSUne+ej71OKW7drzv/LHwUCahR9
MxsUgAAAAAAEAA5tYW51MiwyLjUrMS4xMiwwLDMCGwMFCwkIBwICIgIGFQoJCAsC
BBYCAwECHgcCF4AACgkQilu3a87/yx/JoQ//fABVSdl6LnKmG+rqZZMTi3iBCwZa
8ctfnefaYgH2GDCEu2dCSHxL7Ulii4G82YQUUJL+k+hl684pM0SyhFK7GtJUewn+
YvtOOxBtenYwPVbu7e1Ja+Is1cELdBnIMDag1RX2kjLJ+y20U6hGcMdwVtx2mp8M
xxPJJ0+lhF/OmYVoOdmFtwHYBOivBHjjqdZNXHfYEooCI7uBqTYjDq2x3CTkr4yN
usJ4hu33MynJeFVfZM2mN9mdfh5ySGjf7BI9K+MJmN9rFr19lUp9BKcE7WwTDHPV
SqVnewZABQXBFK3wYikFAA6b3Jfm5ktl8u1KR/24dSLVeSagZHJJHwTG0quas6sU
Twii33as8SmwAxGtNUrZhAK3NLTZ/rENvlymGaO7BKUdAjCDev5WWlRvE7VIQFfg
IycBgG6QpHYBos09KKbcLqidN9fBjUPjknGGHBmjtX/YmDqUqq1TzYZmxixz8iGH
qCTF8mrNC014e4XGJwEMRvxPilsi/fX5A2umQlFTv/i74lfrX10uvMi7mNJD1H2H
GEz/h01u3x/l8lc0RswKuDDhTGuKzRGXI9TekziwIEEPw0C5ARe4knFilpMkpTwq
kSCaY53y9zsjBYuUWHl23rx6bfZi7+vKzd2xW8/sJ15GqF9L4uhoP4xsDLXUCKbf
lAGGsZMV/3nNzhu5Ag0EahR9MwEQAJkNKXtlSoNLXsKtcosPVTT5UnosfJYbFj/E
F6tPyJ5ZVQ5wuy0DmSRbB0lNncMvH0u5Vp34E+n1p+kMIQQo7La3xIfrp7oPUhtn
rxASdheArikHLOIxiaTvdTfKJB7mURVENypKH7BWzEowMFWX52BfVKqyePT58Iv/
0yAGuRKfQpPlvaZPJ5D0vB4jwTXdk7nILalxebNYOoHFUN+Xe3Qp1TJdR87tC6m+
oA1HsMAQ5hD7bF/ZJZf/erpFJSeF1sB4HxCYyAYkjhNUt/3jr2xNJbE89zQEVRcW
WeFdCvX5NE7BxDvnsjbVALOqkXDlIUDKYfaidyz7FEd5SMlZk/O9objUEzN5tyxF
Pk1b+40JTB4Af2jOJkXCS+E/QcZwUm9jl2DsTDHFVgmCFWQOLzG79G51s8z/BqfW
3D7xEhpjIA4RMJDkvsFpwmJqL9NmUoOLJoeuTkJt2llu/KWO+cPUjPiZZqJmIj1w
KcHCK/8N279KQgs8dSroi75qwu0rEfSlmokZSDfs6CuzK1sfjvxuymKL0Xl9B4CS
sFLIqvWQdB/Vk7HqFcLlCjTbROhlzxCR7ywHmCdw+snHRzIa8TCaSqY506JUxwzk
YB1mVt40d/nvr8GjqrpWlrQjXFQc0FL6NVrg53XskcL2EwachtHfeQZeuoAe6SH1
jRekSuqrABEBAAGJAlIEGAEIADwWIQQhUePSmSUne+ej71OKW7drzv/LHwUCahR9
MxsUgAAAAAAEAA5tYW51MiwyLjUrMS4xMiwwLDMCGwwACgkQilu3a87/yx+yGw/+
MgCDmoRpntmeWS6xXc/kQa6sIwHcosOVxxXRPnHd/VWxjZOh4k5FI1wQb9O/chDl
NlFZy6PdUpwm6KZ6TeQwWhVO2PAr3firaBmgFUf0+y6pil4mOYyzFmsiKcAQytrX
dsr+c7CCn4s9rtZ1AcBTnp8BQ4DYY1v5mhg7PPO1NJsy2PV6Gb+XptPBRQf/Q04m
uF7QS8y9gDhxHaHP6//O+JQyyWqWcKVuBZej5kO9V+V1IaRDQuLutQ0DTJUZrP/z
0QYsN4hmcgds8KK6/Nks695BHJsSMcamkG7AyyIxtkyIqngjwVZ0gJurwPhXiFAN
Xytx3LETsjokWnZfDoLfpmEOuHM6jQb7uv5zE5Zaxdcyn+MRo1q5JgXfX1XzXdNX
eXfTUcc4ok77+DDLg392oInSw6fj+ip3gd4oZ9LTHunR/clvg97WoPnQaI+juNmU
R83vvayzHf0frirx7ve4yfXmgQzm+QkNmvOlGfpFMP/TYDBXYO8+tt5qmq7awEEh
ogoDPEsvNDLo7V6C4SsGO+szNHyVTyAU0tiawwsgr1FtTjc+4chWb0eGCrwvhzT2
4JejqtNmdctxrt2KnQppzzaGw3QHuRgSEhHRHc9vP/yZuk5+m09ZSjmGwvXWk57t
yqO65fwQk+qvHuATIhuuohrJ9Bl7hQX0HOwI3lpCT6k=
=+807
-----END PGP PUBLIC KEY BLOCK-----
```
Fingerprint: `2151 E3D2 9925 277B E7A3  EF53 8A5B B76B CEFF CB1F`

The public key is also embedded in every Trojan binary and available on standard keyservers once published.

---

## Supply chain notes

The open-source scanners Trojan wraps (Semgrep, Trivy, Gitleaks, Checkov, Syft) are **read-only by design** — they analyze code, they never write to it. Even in a worst-case upstream compromise, these tools cannot inject code into your project. The primary supply chain risk is Trojan itself, which is why we invest in signing, attestation, and reproducible builds.

Scanner versions are pinned and auto-installed via `trojan init`. If a scanner binary changes unexpectedly between runs, Trojan will warn you.
