# Why Entitlements.plist says so little

## Do not put XML comments in Entitlements.plist

`plutil -lint` accepts comments. **`codesign` does not.** It parses entitlements
with AMFI, which is far stricter, and a comment block there fails the build with:

```
Failed to parse entitlements: AMFIUnserializeXML: syntax error near line 32
failed to bundle project: failed codesign application: failed to sign app
```

That cost one CI run on `desktop-v0.3.0`. Keep the plist bare and keep the
reasoning here.

To check a change before pushing, sign any throwaway binary locally:

```sh
cp /bin/echo /tmp/entsprobe
codesign --force --sign - --entitlements Entitlements.plist /tmp/entsprobe
codesign -d --entitlements - /tmp/entsprobe
```

Ad-hoc signing (`--sign -`) runs the same AMFI parser, so this reproduces the
failure without an Apple certificate and without waiting on CI.

## Why only `allow-jit`

Every entitlement is a hole in the hardened runtime, and this is a security
product. The set is deliberately minimal; add to it only with a recorded reason.

**`com.apple.security.cs.allow-jit`** — the UI is a WKWebView running
JavaScript. WebKit executes JS in its own out-of-process WebContent service
carrying Apple's entitlements, so this is belt-and-braces rather than strictly
required. It is here because its absence produces a silent white window rather
than a clear error, which is expensive to diagnose.

## Considered and deliberately omitted

**`com.apple.security.cs.allow-unsigned-executable-memory`** and
**`com.apple.security.cs.disable-library-validation`** — both looked necessary
because `trojan init` downloads third-party scanners (Semgrep, Nuclei) into
`~/.trojan/bin` and runs some of them through `python3`
(`internal/config/init.go`). They should not be needed: those scanners run as
**separate child processes**, and a child does not inherit this process's
hardened runtime. These entitlements only matter for code loaded *into* the
Trojan process.

Add one only if a scan genuinely fails on a hardened build, and note here which
scanner forced it.

**`com.apple.security.cs.allow-dyld-environment-variables`** — only needed if we
start injecting `DYLD_*` into the app itself. We do not.

## Not App Sandbox

`com.apple.security.network.client` and friends do not belong here. The app is
not sandboxed; it deliberately reads arbitrary project directories and spawns
scanners, neither of which survives sandboxing.
