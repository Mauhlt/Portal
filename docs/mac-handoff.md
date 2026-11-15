# Mac handoff (temporary)

**Delete this file in the final commit of the Mac/iPhone session**, once the
checklist in `docs/mac-session-portal.md` passes. It is scaffolding for an
agent session on the owner's Mac, not documentation.

## Set up the Mac session

1. Install the agent and sign in with the owner's account.
2. Get Zig with ZVC: download `zvc-aarch64-macos` from the latest ZVC release
   on GitHub, `chmod +x` it, run it once (it installs ZVC's known-good Zig),
   then `zvc install --from <Portal checkout>` for Portal's exact version, and
   add the folder it prints to PATH.
3. Clone Portal (and, only to edit them, Renderer, SpeechToText and the other
   repos it pins) side by side. Portal fetches its dependencies itself.
4. Copy the owner's memory folder from the Windows desktop
   (`~/.claude/projects/<Portal path with / as ->/memory/`) so the standing
   rules apply: commits as the owner with no attribution lines, all code in
   Zig, event-driven only, ask before every push, Renderer stays app-neutral,
   and only the approved folders.
5. Copy the privacy-check tool (`.portal-scrub`, built from `scrub.zig`) and
   run `git fast-export <branch> | scrub check --identity "<owner>"` before
   any push: it must report 0 problems.

## Where things stand

Done and tested on Windows: the iPhone app compiles (`zig build ios-check`)
with the in-app and background tunnel, dictation on Core ML with the desk's
base.en model and synced adapter, samples sent home, rotation, 44 pt touch
targets, and the one-command signer. Never run on a Mac or iPhone: all of it.
The `ios` GitHub workflow builds the unsigned app on GitHub's Macs.

## The work, in order

1. `docs/mac-session-portal.md`: build the kit, sign and install
   (`portal-ios.conf` with team ID and paid/free, then
   `./portal-ios-sign --install --launch`), first run, pairing, tunnel,
   dictation, screen and touch checks.
2. SpeechToText's `docs/mac-session.md`: the Core ML probes and `coreml-dev`.
3. Fix what fails, re-run, commit, check, ask, push.

The owner provides: bundle ID, Apple team ID, paid or free account, and the
provisioning profiles (paid: the app and `<bundle id>.tunnel`).
