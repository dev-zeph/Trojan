# Auto-update setup (one time)

The app checks GitHub Releases for a newer version on launch and every 4 hours,
and offers "Update now" / "Later". Updates are signed with a key only you hold,
so nobody else can push code to your users. Until steps 1 to 4 are done, release
builds FAIL (the workflow needs the signing key) and the in-app check does nothing.

## 1. Generate the signing key

```
cd desktop
npx tauri signer generate -w ~/.tauri/trojan.key
```

Pick a password when asked. This writes two files:
`~/.tauri/trojan.key` (private, never commit or share) and
`~/.tauri/trojan.key.pub` (public).

Back up the private key and password somewhere safe (password manager). If you
lose them, installed apps can never be updated again and everyone has to
reinstall by hand.

## 2. Put the public key in the app

```
cat ~/.tauri/trojan.key.pub
```

Copy the whole output and paste it over the placeholder value of
`plugins.updater.pubkey` in `desktop/src-tauri/tauri.conf.json`. Commit it.
(The public key is safe to commit.)

## 3. Add two GitHub secrets

GitHub repo dev-zeph/Trojan > Settings > Secrets and variables > Actions >
New repository secret:

1. `TAURI_SIGNING_PRIVATE_KEY`: the full contents of the file, from
   `cat ~/.tauri/trojan.key`.
2. `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`: the password you chose in step 1.

## 4. Ship a release

Push a `desktop-vX.Y.Z` tag as usual. The workflow builds both platforms,
signs the update files, and adds `latest.json` to the draft release. Then
publish the draft (Releases > edit the draft > Publish). Apps only see a
release once it is published, and `latest.json` must be on the release marked
"Latest". The release notes you write become the "what's new" text in the prompt.

## 5. Verify

- Open `https://github.com/dev-zeph/Trojan/releases/latest/download/latest.json`.
  It should show the new `version`, plus `darwin-aarch64` and `windows-x86_64`
  entries, each with a long `signature` and a `url`.
- The release should list: the .dmg, `Trojan.app.tar.gz` and its `.sig`, the
  Windows setup .exe and its `.sig`, the .msi and its `.sig`, and `latest.json`.
- Updates only help builds that contain the updater, so the first real test is
  the release AFTER this one: install the updater-enabled build, publish a
  newer tag, open the installed app, and the prompt should appear.

## Existing users (v0.3.x, v0.4.x)

Those builds have no updater. They must download and install the new version by
hand once. After that, updates are automatic.

## macOS notes

The updater signature (this key) is separate from Apple codesigning. The
workflow signs and notarizes the Mac app when the Apple secrets are set. If they
are not set the app is unsigned: updates still install, because the updater
verifies its own signature and the downloaded file is written by the app itself
(no download quarantine flag), but the very first install from the .dmg still
hits Gatekeeper. Updating needs write access to where Trojan.app sits
(normally /Applications); if it fails the app logs it and keeps working.
