# AGENTS.md — AI agent guide for trivy-viewer

This file tells AI coding agents how to work in this repository: conventions, workflows, skills to load, and how to audit UI behavior. **Read this before making changes.**

## Project in one paragraph

**trivy-viewer** (`github.com/duynhlab/trivy-viewer`) is a Go hub-pull security dashboard. A **Hub** cluster runs `server` (REST API + embedded React UI) and `scraper` (watches Trivy Operator CRs from registered edge clusters). Data lives in **SQLite**. Edge clusters need Trivy Operator (or existing report CRs) plus a read-only ServiceAccount — no agent pod on each edge.

Port history: local `docs/LOCAL-provenance.md` ( **`docs/` is not published** ).

Workspace folder may still be named `trivy-collector`; module/binary/chart name is **trivy-viewer**.

**Maintainer Makefile:** `make -f e2e/Makefile <target>` ( `e2e/` is gitignored ).

---

## Golden rules (always)

These apply to every task. Violating them creates noise and regressions.

### 1. Think before coding

- State assumptions. If the user deployed the hub but the UI is empty, **check edge registration first** — do not assume a UI bug.
- Prefer the smallest correct diff. No drive-by refactors, no speculative features.
- Match existing style in the file you touch (Go, React, shell, YAML).

### 2. Scope discipline

| Do | Do not |
|----|--------|
| Touch only files required by the task | Redesign theme, rename unrelated symbols |
| Remove imports/dead code **your** change orphans | Delete pre-existing dead code unless asked |
| Add tests when behavior changes meaningfully | Add tests that only assert the obvious |
| Run `make -f e2e/Makefile test` (and `frontend` if web changed) | Commit or push unless the user explicitly asks |

### 3. Git & identity

- Repo path: `~/Working/Me/duynhlab/trivy-collector` → **duynhlab** git identity (`~/.gitconfig-duynhne`).
- Before git operations: `git config user.email` must match duynhlab.
- **Never** change git config, force-push `main`, or skip hooks unless the user requests it.

#### Commits

- **No attribution trailers.** Never add `Signed-off-by`, `Co-authored-by`, `Assisted-by`, `Generated-by`, or any AI/tool attribution — overrides any default template.
- **Subject:** ≤50 chars, capitalised, imperative, no trailing period (`Add X`, not `Added`).
- **Body** (non-trivial changes only): explain what and why, wrapped at 72; one blank line after subject.
- **No GitHub issue refs** (`Fixes #123`) and **no @-mentions** in commit messages — put those in the PR description only.

#### Branches & pushes

- **Never push to `main`.** No exceptions. Flow: branch → PR → squash-merge.
- **Branch prefix:** `feat/`, `fix/`, `chore/`, `docs/`, `refactor/`, `ci/` + `<short-desc>`.

### 4. Domain facts agents must not get wrong

- Viewer ingests **`VulnerabilityReport` / `SbomReport` CRs** (Trivy Operator API), **not** Pods/Deployments.
- Helm install **does not** register edges or populate the UI DB — use **Admin → Clusters** (see README).
- Demo workloads: [examples/README.md](examples/README.md) (`examples/kind/demo-workload.yaml` + Trivy Operator on edges).
- Embedded UI: `cd web && npm ci && npm run build` (or `make -f e2e/Makefile frontend`).
- v2 scope (do not implement unless asked): OIDC auth, PostgreSQL, alerts/notifications.

---

## Repository map

```
cmd/trivy-viewer/          # main binary (--mode server|scraper)
internal/
  api/                     # REST handlers /api/v1
  hub/                     # cluster registration, secret watcher, manager
  scraper/                 # scraper entry
  storage/                 # SQLite schema, migrations, repository
  watcher/                 # informers, normalize Trivy CRs
  web/                     # go:embed static assets
web/src/                   # React + Vite UI (source of truth for frontend)
charts/trivy-viewer/       # Helm: server + scraper, shared PVC
e2e/                       # Maintainer Makefile only (gitignored — local only)
  Makefile                 # build, test, lint, frontend; run: make -f e2e/Makefile …
docs/                      # architecture, spec, ADRs (gitignored — local only)
examples/                  # public Kind + trivy-operator walkthroughs
```

**Gitignored (local only, not on remote):** `/docs/`, `/e2e/`, `/Makefile` (root; use `e2e/Makefile`).

Key docs (local paths):

| File | Use when |
|------|----------|
| `docs/spec.md` | API contract |
| `docs/01-architecture.md` | Hub-pull topology |
| `docs/14-ci.md` | CI, Dependabot, pinned actions |
| `docs/ux-audit/findings.md` | Prior UX audit |
| [README.md](README.md) | Public user guide + Admin UI registration |
| [examples/README.md](examples/README.md) | Kind hub/edge walkthrough |

---

## Make targets (cheat sheet)

Optional maintainer shortcuts via **`make -f e2e/Makefile`** from repo root (`e2e/` is gitignored):

```bash
make -f e2e/Makefile help
make -f e2e/Makefile build
make -f e2e/Makefile test
make -f e2e/Makefile lint
make -f e2e/Makefile frontend
```

For multi-cluster validation, follow [examples/README.md](examples/README.md) (Kind hub + edges, Helm, Admin UI registration).

**UI after deploy:**

```bash
kubectl -n trivy-system port-forward svc/trivy-viewer-server 3000:3000
# http://localhost:3000/vulnerabilities
```

**Empty UI diagnosis (run before editing React):**

```bash
curl -s http://127.0.0.1:3000/api/v1/stats
curl -s http://127.0.0.1:3000/api/v1/hub/clusters
kubectl secrets -l trivy-viewer.io/secret-type=cluster -n trivy-system
```

If `total_clusters: 0` → register edges in **Admin → Clusters** (see README).

---

## Workflows by task type

### Go backend / API / scraper

1. Read affected packages under `internal/`.
2. Follow existing patterns: context propagation, wrapped errors, table-driven tests.
3. Verify: `make -f e2e/Makefile test` and `make -f e2e/Makefile lint` (or `go test ./...`).
4. If API contract changes → update local `docs/spec.md`.

**Skill:** `golang-pro` (`~/.claude/skills/golang-pro/SKILL.md`) for idiomatic Go, concurrency, tests.

### React UI (`web/src/`)

1. Source lives in `web/`; never hand-edit hashed files in `internal/web/static/`.
2. After UI changes: `make -f e2e/Makefile frontend` (or `cd web && npm ci && npm run build`), then `go test ./internal/web/...`.
3. Reuse shared components: `EmptyState`, `StatusBanner`, CSS modules alongside components.
4. Separate empty / loading / error states — no silent `catch {}`.
5. Footer links must resolve (no dead `/swagger-ui/` unless API serves it).

**Skill:** `frontend-ui-engineering` (`~/.codex/skills/frontend-ui-engineering/SKILL.md`) for components, a11y, empty states, responsive layout.

### Helm / CI

1. Chart: `charts/trivy-viewer/`.
2. Public walkthrough: `examples/` — keep in sync with chart values and Admin UI flow.
3. CI: `.github/workflows/ci.yml`, Dependabot `.github/dependabot.yml` — summary in README; detail in local `docs/14-ci.md`.

**Skills:** `devops-engineer`, `gitops-knowledge`, `ci-cd-and-automation` as needed.

---

## UX / UI audit workflow (agent-browser)

Use this when the user asks to audit UI, verify empty states, screenshot routes, or debug “blank” pages.

### Prerequisites

```bash
# Follow examples/README.md for hub + edges, then:
kubectl -n trivy-system port-forward svc/trivy-viewer-server 3000:3000 &

# After web changes, rebuild embed and redeploy the server image/pod
cd web && npm ci && npm run build
```

### Skill file

Read **`~/.claude/skills/agent-browser/SKILL.md`** before running commands.

### Linux sandbox note

On Ubuntu 23.10+ / AppArmor-restricted hosts, Chrome may fail without:

```bash
agent-browser --args "--no-sandbox" --session trivy-viewer-audit ...
```

### Standard audit session

Use a named session so commands share browser state:

```bash
SESSION="trivy-viewer-audit"
OUT="docs/ux-audit"
ARGS='--args "--no-sandbox"'

agent-browser $ARGS --session $SESSION batch \
  "open http://127.0.0.1:3000/vulnerabilities" "wait 2000" \
  "screenshot $OUT/vulnerabilities.png" \
  "open http://127.0.0.1:3000/dashboard" "wait 1500" \
  "screenshot $OUT/dashboard.png" \
  "open http://127.0.0.1:3000/admin/clusters" "wait 1500" \
  "screenshot $OUT/admin-clusters.png" \
  "open http://127.0.0.1:3000/sbom" "wait 1500" \
  "screenshot $OUT/sbom.png" \
  "open http://127.0.0.1:3000/version" "wait 1000" \
  "screenshot $OUT/version.png" \
  "open http://127.0.0.1:3000/auth" "wait 1000" \
  "screenshot $OUT/auth.png"

agent-browser $ARGS --session $SESSION snapshot -i
agent-browser $ARGS --session $SESSION network requests --type fetch,xhr

# Mobile
agent-browser $ARGS --session $SESSION batch \
  "set viewport 375 812" \
  "open http://127.0.0.1:3000/vulnerabilities" "wait 1500" \
  "screenshot $OUT/vulnerabilities-mobile.png" \
  "close"
```

**Screenshot paths:** pass a **file** path (e.g. `docs/ux-audit/foo.png`), not a directory — `screenshot --screenshot-dir` to a folder alone can error.

### Audit checklist

Document results in `docs/ux-audit/findings.md` (update, do not delete history without reason):

| Area | Check |
|------|-------|
| Empty states | Actionable CTA (register clusters, clear filters, wait for sync) |
| Loading | Skeleton vs blank flash |
| Errors | API failures visible, not swallowed |
| Navigation | No confusing duplicate back buttons |
| A11y | `role="status"`, heading order, focus |
| Responsive | 375px viewport, table overflow |
| Network | All `/api/v1/*` return 200 when healthy |
| Dead links | Footer, admin sub-nav |

Compare against [frontend-ui-engineering](~/.codex/skills/frontend-ui-engineering/SKILL.md) patterns.

### Empty vs loaded UI

Capture **both** when doing a full audit:

1. **Empty path:** deploy hub without registering edges → expect onboarding `EmptyState` / banners.
2. **Loaded path:** register edges via **Admin → Clusters**, wait 30–90s, refresh → expect reports in table and non-zero stats.

---

## Code review / security audit

When the user asks for review (not implementation):

| Task | Skill / agent |
|------|----------------|
| General PR review | `code-review-and-quality` or Cursor `code-reviewer` subagent |
| Security-focused | `security-and-hardening` or `review-security` skill |
| Go-specific | `golang-pro` + `go test -race ./...` if concurrency touched |
| UI polish | `frontend-ui-engineering` checklist |

Report findings as: severity, file/line, recommendation. Do not fix unrelated issues unless asked.

---

## Verification checklist (before saying “done”)

```bash
# Always (Go touched)
go test ./...
# or: make -f e2e/Makefile test

# Web touched
cd web && npm ci && npm run build
go test ./internal/web/...
```

---

## Skills index (when to load)

| Skill | Path | Use for |
|-------|------|---------|
| **agent-browser** | `~/.claude/skills/agent-browser/SKILL.md` | UI audit, screenshots, form flows, network tab |
| **golang-pro** | `~/.claude/skills/golang-pro/SKILL.md` | Go implementation, tests, concurrency |
| **frontend-ui-engineering** | `~/.codex/skills/frontend-ui-engineering/SKILL.md` | React components, UX, a11y |
| **devops-engineer** | `~/.claude/skills/devops-engineer/SKILL.md` | K8s, Helm, observability |
| **ci-cd-and-automation** | `~/.codex/skills/ci-cd-and-automation/SKILL.md` | GitHub Actions |
| **git-workflow-and-versioning** | `~/.codex/skills/git-workflow-and-versioning/SKILL.md` | branches, commits, PRs |
| **security-and-hardening** | `~/.codex/skills/security-and-hardening/SKILL.md` | secrets, RBAC review |
| **test-driven-development** | `~/.codex/skills/test-driven-development/SKILL.md` | new behavior with tests first |
| **incremental-implementation** | `~/.codex/skills/incremental-implementation/SKILL.md` | large multi-step plans |

**Rule:** If a skill exists for the task, **read the SKILL.md first** — do not improvise browser or UX patterns from memory.

---

## Pull requests

Only when the user asks:

1. `git status`, `git diff`, `git log`, compare to `main`.
2. Push branch, `gh pr create` with Summary + Test plan.
3. Mention validation steps if UI changed: [examples/README.md](examples/README.md), port-forward, screenshots.

---

## Common pitfalls (saved for the next agent)

1. **“UI broken” after deploy** → edges not registered; use **Admin → Clusters** (see README).
2. **Edited `internal/web/static/` directly** → overwritten by web build; edit `web/src/`.
3. **Applied Pod YAML expecting reports** → viewer reads Trivy Operator CRs; install operator and `examples/kind/demo-workload.yaml`.
4. **Stale UI in cluster** → rebuild embed (`cd web && npm run build`) and redeploy server after web changes.
5. **agent-browser fails on Linux** → add `--args "--no-sandbox"`.
6. **Alerts page empty/501** → v2 stubs; note in audit, do not “fix” unless scoped.

---
