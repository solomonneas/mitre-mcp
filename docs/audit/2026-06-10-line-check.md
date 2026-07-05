# line-check report: mitre-mcp (2026-06-10)

## Verdict
mitre-mcp is healthy and close to exemplary on the inside: 82 tests pass in under a second, typecheck is clean, the README's 39-tool count matches the code exactly, agent guidance (AGENTS.md plus `scripts/verify`) is among the best in the fleet, brigade wiring reports zero issues, and there are zero TODO markers and zero open issues. The problem is at the boundary: the npm package and the v2.0.0 tag are 9 commits stale and predate commit bdc13d0, the security hardening that scoped the global TLS disable, added ID path encoding, and gated SOC write tools. Everyone installing from npm today gets the unhardened build. The single most important thing to do is bump to v2.0.1 and tag a release; second is fixing the CI gate, which currently ignores test failures (`continue-on-error: true`) and never runs typecheck. Needs work, but all of it is cheap.

## Scorecard
| Station | Score (0-5) | Summary |
|---|---|---|
| 1. Docs and onboarding | 4 | Thorough README, commands verified against package.json, tool counts match code (39 confirmed); minor project-structure drift (missing `src/soc/util.ts`, `tests/soc-security.test.ts`) |
| 2. Agent-readiness | 5 | AGENTS.md with Definition of Done, single `scripts/verify` entrypoint, SOC safety prohibitions, brigade handoff doctor and memory care scan both clean |
| 3. Tests and CI | 3 | 82/82 tests pass locally, security-specific test file exists; but CI masks test failures and skips typecheck, so the green badge proves only that the build compiles |
| 4. Hygiene | 4 | .gitignore covers `.claude/`, `.codex/`, `memory/`, `.brigade/`; MIT LICENSE; content-guard pre-push hook; no secrets or internal hosts found; one stale remote branch |
| 5. Structure | 4 | Clean module layout (tools/, soc/, data/), largest file 671 lines, register-and-wire pattern documented; server version hardcoded separately from package.json; undici one major behind |
| 6. Release hygiene | 2 | No CHANGELOG; v2.0.0 tag and npm publish (2026-04-30) are 9 commits behind main including the security fix; publish workflow correctly skips re-publishing but nothing has bumped the version |
| 7. TODO and issue mining | 5 | Zero TODO/FIXME/HACK markers in the tree, zero open GitHub issues |

## Findings

### [HIGH] Cut a v2.0.1 release so npm users get the security hardening
- **Station:** Release hygiene
- **Where:** repo-wide (package.json:3 still `2.0.0`; `git log v2.0.0..main` shows 9 commits)
- **What:** npm `mitre-mcp@2.0.0` was published 2026-04-30. Commit bdc13d0 (2026-06-08) replaced the process-global TLS disable with per-request undici agents, added ID validation/encoding before path interpolation, and gated the three SOC write tools behind `writesAllowed()`. None of that is in the published package; the publish job also skips unless the version is new, so it cannot ship until the version bumps.
- **Why it matters:** Anyone installing from npm with `*_VERIFY_SSL=false` runs with certificate validation disabled process-wide, with unencoded IDs spliced into SOC API paths and ungated write tools. The fix exists but is not delivered.
- **Fix:** Bump `package.json` to 2.0.1 (also update the hardcoded version in `src/index.ts:34`, see the medium finding), run `./scripts/verify`, commit, `git tag v2.0.1`, push the tag. CI publishes automatically.
- **Effort:** S

### [HIGH] Remove `continue-on-error: true` from the CI test step
- **Station:** Tests and CI
- **Where:** .github/workflows/ci.yml:24-25
- **What:** The `npm test` step in the `test` job carries `continue-on-error: true`, so a failing test suite still produces a green run and a green badge, and still allows the `publish` job to proceed on tags.
- **Why it matters:** The CI gate is decorative. A regression can merge, tag, and publish to npm with every check green.
- **Fix:** Delete the `continue-on-error: true` line from ci.yml.
- **Effort:** S

### [MEDIUM] Make CI run `./scripts/verify` so typecheck gates merges
- **Station:** Tests and CI
- **Where:** .github/workflows/ci.yml:22-25 and scripts/verify:2-3
- **What:** `scripts/verify` says "CI and AGENTS.md both defer to this file, so the gate lives in exactly one place," but CI runs `npm run build` and `npm test` directly and never runs `npm run typecheck`. The comment is wrong and `tsc --noEmit` errors cannot fail CI.
- **Why it matters:** The verify entrypoint silently drifts from what CI enforces, and type errors that tsup's bundler tolerates pass CI.
- **Fix:** Replace the build/test steps in the `test` job with a single `- run: ./scripts/verify` step (this also subsumes the continue-on-error fix above in one edit).
- **Effort:** S

### [MEDIUM] Derive the MCP server version from package.json
- **Station:** Structure
- **Where:** src/index.ts:34
- **What:** `new McpServer({ ... version: "2.0.0" ... })` hardcodes the version separately from package.json. They match today and will drift on the v2.0.1 bump this audit recommends.
- **Why it matters:** Clients negotiating with the server will report a stale version, which misleads debugging ("which build is this?") right when a security-relevant release lands.
- **Fix:** Import it: `import pkg from "../package.json" with { type: "json" }` (tsup inlines it) and pass `version: pkg.version`, or read it via `createRequire`. Add a one-line test asserting the two match if staying manual.
- **Effort:** S

### [MEDIUM] Add a CHANGELOG
- **Station:** Release hygiene
- **Where:** repo-wide (no CHANGELOG.md tracked)
- **What:** There is no CHANGELOG. The jump from 1.0.0 to 2.0.0 (39 tools, SOC integration, Navigator) and the pending security fix are documented only in commit messages.
- **Why it matters:** npm consumers deciding whether to upgrade, especially for a security release, have nothing to read. Release notes are how the v2.0.1 hardening gets communicated.
- **Fix:** Create CHANGELOG.md (Keep a Changelog format) with entries for 1.0.0, 2.0.0, and an Unreleased section listing the security hardening; fold it into the v2.0.1 release. Per the user's release cadence rule, accumulate under Unreleased between releases.
- **Effort:** S

### [LOW] Fix README project-structure drift
- **Station:** Docs and onboarding
- **Where:** README.md:446-456
- **What:** The Project Structure tree omits `src/soc/util.ts` (the security-critical shared helpers AGENTS.md points at) and `tests/soc-security.test.ts`.
- **Why it matters:** Small trust leak: a reader auditing the security story from the README will not see the file that implements the gates or the test that covers them.
- **Fix:** Add both lines to the tree in README.md.
- **Effort:** S

### [LOW] Delete the stale feature/soc-integration remote branch
- **Station:** Hygiene
- **Where:** origin/feature/soc-integration
- **What:** The branch's work was squashed into main (a944432) but the remote branch survives with unmerged-looking history, including two `auto-backup:` commits.
- **Why it matters:** Contributors and agents see an unmerged feature branch and may try to reconcile or build on it; the auto-backup commits are noise.
- **Fix:** `git push origin --delete feature/soc-integration`
- **Effort:** S

### [LOW] Evaluate the undici 8 upgrade
- **Station:** Structure
- **Where:** package.json:48 (undici ^7.27.2; latest 8.4.1)
- **What:** undici is one major behind. `npm audit` is clean (0 vulnerabilities) and 7.x still receives fixes, so this is currency, not exposure. @types/node has a trivial patch available.
- **Why it matters:** The per-request TLS scoping leans on undici's Agent/dispatcher API; the longer the major gap grows, the riskier the eventual migration of that security-sensitive code.
- **Fix:** Read the undici 8 changelog for Agent/dispatcher breaking changes, bump, run `./scripts/verify` plus `tests/soc-security.test.ts` per AGENTS.md, and call out the change explicitly. Do it after the v2.0.1 release, not in it.
- **Effort:** M

### [INFO] Brigade and memory wiring are clean
- **Station:** Agent-readiness
- **Where:** .brigade/, .claude/memory-handoffs/
- **What:** `brigade handoff doctor` reports all ok (4 processed handoffs, 0 pending); `brigade memory care scan` reports 0 cards, 0 issues. `memory/` and `.brigade/` are gitignored as AGENTS.md requires.
- **Why it matters:** Worth knowing this station needs nothing.
- **Fix:** None.
- **Effort:** S

## Backlog
1. [HIGH/S] Cut a v2.0.1 release so npm users get the security hardening (Release hygiene)
2. [HIGH/S] Remove `continue-on-error: true` from the CI test step (Tests and CI)
3. [MEDIUM/S] Make CI run `./scripts/verify` so typecheck gates merges (Tests and CI)
4. [MEDIUM/S] Derive the MCP server version from package.json (Structure)
5. [MEDIUM/S] Add a CHANGELOG, shipping the security notes with v2.0.1 (Release hygiene)
6. [LOW/S] Fix README project-structure drift (Docs and onboarding)
7. [LOW/S] Delete the stale feature/soc-integration remote branch (Hygiene)
8. [LOW/M] Evaluate the undici 8 upgrade after the release (Structure)

## Not checked
- Runtime behavior of the MCP server against live ATT&CK data or live SOC platforms (Wazuh/TheHive/Cortex/MISP); AGENTS.md prohibits SOC operations during review and no instances were contacted.
- `scripts/proxmox_install.sh` execution; AGENTS.md forbids running it on this machine. Only read for secrets.
- npm package tarball contents (`npm pack` would write an artifact; audit is read-only). `files` allowlist in package.json was reviewed instead.
- Test quality beyond pass/fail and file coverage by area; no mutation testing or coverage measurement was run.
- `node_modules/` and `dist/` per skill rules (generated/vendored).
- GitHub repo settings (branch protection, secrets configuration for NPM_TOKEN); only workflow files and run history were inspected.
