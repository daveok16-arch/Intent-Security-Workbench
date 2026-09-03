# AGENTS.md — Intent Security Workbench

Persistent memory for AI agents working in this repo. Keep this file current as the project evolves.

## What This Is

Modular, production-grade platform for **authorized** multi-program security research (Immunefi, HackenProof, Cantina, HackerOne, Custom), blockchain ecosystems (EVM, Solana/Rust, Clarity/Stacks, Move), and Web/API targets. Currently at **Phase 0** (foundational architecture); Phases 1-3 planned in `docs/PHASES.md`.

## Commands (npm only — see Quirks)

```bash
npm install --legacy-peer-deps   # REQUIRED flag; plain npm install hits an arborist bug
npm run dev                        # dev server (tsx server.ts), port 3000
npm run test                       # vitest run (51 tests / 11 files as of Phase 0)
npm run lint                       # tsc --noEmit
npm run build                      # vite build + esbuild server bundle - dist/
npm run clean                      # rm -rf dist server.js
npx tsx cli.ts engines list|check # CLI (also: evidence, provenance, events subcommands)
```

## Architecture Map

| Path | Responsibility |
|---|---|
| `packages/core/` | Canonical domain enums + 10-state finding state machine (`validateFindingTransition`, `VALID_FINDING_TRANSITIONS`) |
| `adapters/programs/` | Bounty-platform policy/scope normalizers |
| `adapters/targets/` | Ecosystem-specific target validation (EVM, Solana, Clarity, Move, Web/API) |
| `engines/` | `BaseEngine` + `EngineRegistry` + 10 engine classes (real `check_availability()`, execute deferred to Phases 1-2) |
| `packages/orchestrator/` | Typed job queue, structured logs, retries, WebSocket telemetry |
| `packages/evidence/` | SHA-256 artifact hashing, filesystem storage, provenance graph/chain, append-only event store, source snapshots |
| `sandbox/` | Strict command-boundary enforcer (no chains/pipes/destructive verbs; exact-scope match) |
| `packages/agent-runtime/` | Authorization gate + execution context (thin wrapper — Phase 3 will build real agent loop) |
| `apps/api/db_store.ts` | In-memory domain store + artifact storage wiring |
| `apps/api/python/` | FastAPI **stub** — health/readiness/version only; honestly reports `not_wired` |
| `src/` | React workbench UI (12 views) + `context/WorkbenchContext.tsx` + `types.ts` (client-side duplicated enums) |
| `server.ts` | Express + WebSocket server (port 3000) |
| `docs/` | PHASES, ARCHITECTURE, ENGINE_INTERFACE, JOB_SYSTEM, SECURITY_MODEL, EVIDENCE_MODEL, DATA_MODEL |

## Non-Negotiable Invariants (never violate)

1. **No fake findings / no synthetic scanners** — never claim an engine executed, a vuln verified, or a proof generated unless real machine-verifiable evidence exists.
2. **Deterministic SHA-256** — every artifact hashed over exact raw byte payload (`computeArtifactSHA256`).
3. **Strict 10-state finding FSM** — transitions to `VALIDATED`/`CONFIRMED` blocked without linked verifiable evidence artifacts.
4. **Engine availability truthfulness** — missing binaries must return `NOT_INSTALLED` / `UNAVAILABLE` / `BROKEN`, never success.
5. **Sandbox discipline** — reject compound commands, control chars, redirection into protected paths, destructive verbs; scope must be exact-match.

## Quirks & Gotchas (read before touching anything)

- **`npm install` fails** with npm 10 arborist bug `Cannot read properties of null (reading 'edgesOut')`. Always use `npm install --legacy-peer-deps`. Node 22 + npm 10.9.8 verified. No bun — do not use `bun.lock` unless bun gets installed.

- **Terminal `cat` display artifact**: raw `cat` makes valid code look mangled (e.g. `this.` renders like `this.`). Files are clean — verify suspicion with the file editor / `cat -n` or `python3 -c "print(repr(open(f).read()))"` before "fixing". Do NOT mass-rewrite files chasing this phantom corruption.


- **In-memory store**: programs/targets/investigations/jobs findings exist only in `Map`s — no DB persistence yet. Sessions lose data on restart (by design, Phase 0).
- **Engine placeholders**: `execute()` throws `deferred to integration phase` for all engines except `git-source-integrity` (real git operations). Availability checks are real for all 10.
- **Python API**: stub by design — do not extend it to full CRUD until the dual-language story is decided (avoid TS/Python domain drift).


- **Client types duplication**: `src/types.ts` mirrors `packages/core` enums — keep in sync manually (candidate for dedup later).
- **`metadata.json`**: claims `MAJOR_CAPABILITY_SERVER_SIDE_GEMINI_API` but no server-side Gemini code exists yet — flag if implementing or remove.
- **No CI** — none configured; consider adding before multi-agent collaboration.

## Assist Agents (INSTALLED — opencode + aider)

Two assist coding agents are live in this environment and act as a team with the project-manager agent:

| Agent | Version | Install method | Binary | Notes |
|---|---|---|---|---|
| opencode | 1.18.27 | `npm install --prefix "$HOME/.npm-global" -g opencode-ai` | `$HOME/.npm-global/bin/opencode` | Headless-capable: `opencode run "<msg>"`; supports `--print-logs`, `--log-level`. |
| aider |å0.86.2 | `uv tool install aider-chat` + `audioop-lts` backport (see Gotchas) | `$HOME/.local/bin/aider` | Headless-capable (`-m "<msg>"`, `--model`, `--no-auto-commits`, `--lint`, `--test`, `--yes`); repo has no LLM keys configured — set env keys before expecting agent responses. |

**PATH** (both already appended to `~/.bashrc`):
```bash
export PATH="$HOME/.npm-global/bin:$HOME/.local/bin:$PATH"
```

**Usage patterns (headless, from repo root)**:
- opencode: `opencode run "explain engines/engine_registry.ts"` — or `opencode` interactive.
- aider: `aider -m "implement xxx" --no-auto-commits` — or `aider` interactive..

## Session Log (resume point — READ FIRST in new sessions)

> Kept current by the project-manager agent each session. When a new session begins, read this block to restore full context without digging through history.



## Session 1 — 2026-09-03 (project kickoff)

- **Goal**: Boss appointed project manager; audit repo; pick/install two assist agents; update AGENTS.md so sessions are lossless..
- **Audit verdict (Phase 0)**: 51/51 tests pass, `lint` clean, `build` OK, dev server boots (UI 200, `/api/health` phase 0; WS 200). 9/10 engines honestly `NOT_INSTALLED`, `git-source-integrity` → `AVAILABLE` (real `git 2.47.3`). No fake data anywhere (anti-fabrication enforced).
- **Gaps documented**: real engine `execute()` deferred (except git-source-integrity; in-memory domain store (no DB persistence; Python FastAPI `= stub (health/readiness/version only; agent-runtime thin (Phase 3 needs build-out; `src/types.ts` duplicates core enums (drift risk; `metadata.json` claims `MAJOR_CAPABILITY_SERVER_SIDE_GEMINI_API` but no server-side Gemini code exists; no CI..
- **Agents installed**: opencode 1.18.27 (npm user-prefix) + aider 0.86.2 (uv tool + audioop-lts fix.. PATH wired into `~/.bashrc` (both `~/.npm-global/bin` and `~/.local/bin`).
- **Environment quirks solved this session**:
  - `npm install` → arborist bug — always `npm install --legacy-peer-deps`..
  - aider on Python 3.13 → `ModuleNotFoundError: No module named 'pyaudioop'` — fixed via `uv pip install --python /home/openhands/.local/share/uv/tools/aider-chat/bin/python audioop-lts`.
  - Terminal `cat` render artifact (`this.` looks mangled)→ files are clean; verify via `cat -n`/editor/Python repr before "fixing" anything..
- **Open items awaiting boss**: ① phase plan (roadmap conversion);② commit vs delete `package-lock.json`;③ any engine tooling to install for Phases 1-2..
- **Decisions so far**: boss wants two assist agents; selected lineup = opencode + aider (done); `AGENTS.md` created as shared onboarding/session memory..
- **Git pushed (2026-09-03 late session)**: rebase onto force-updated `origin/main` (remote contained major Phase-1 commit `46af403` — Scope & Target Authorization Subsystem, Static Analysis Engine, Source Package, new components/tests, `bun.lock`, `docker-compose.yml`, `usr/local/bin/semgrep` bin, `.test_fixtures/`). Our original commit bas on old `20826dd`; rebase `--onto` resolved cleanly: took remote's `package-lock.json` (3034 lines, newer than ours raise) and kept only our `AGENTS.md`. Pushed as `617e805` → `origin/main`. **Remote owns the lockfile story now** — if `npm install` is needed, use remote's lockfile + `--legacy-peer-deps`, not our earlier one..
- **IMPORTANT — repo is now Phase 1-ish**: remote commit adds real scope/target authorization (`ScopeDecisionEngine`, `InvestigationGate`, `GitSourceProvider`, real `static_analysis` engine, integration tests `phase1_end_to_end`, `program_adapters`, `scope_decision_engine`, `static_analysis`, `git_source_provider`, `investigation_gate`). Re-audit invariances/tests against new code before next phase work (51-test Phase-0 suite may now differ; run `npm test` fresh).
- **Current open items**: ① boss's phase plan roadmap;② (resolved: lockfile committed via remote's version);③ Phase-1/2 engine tooling decisions.

## Agent Coordination

Both agents + project-manager share this AGENTS.md as onboarding/session memory. When any agent makes structural changes, update this file (architecture map, invariants, gotchas, session log) so others stay alignedand sessions resume losslessly. The project-manager agent owns keeping the Session Log current (append an entry per session; prune older entries to the last 2-3 if it grows..
