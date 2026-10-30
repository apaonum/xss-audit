# xss-audit

A read-only, static **XSS audit** of a frontend codebase. It searches 14 sink/source layers, traces every match from source to sink, and writes `xss-audit-report.md` with High/Medium/Low findings and fixes.

It covers React/Next.js first, plus Vue, Angular, Svelte, Lit, Knockout, Alpine, and Ember. The layers include HTML, attribute, URL, JS, and CSS sinks, JSON-in-script `</script>` breakout, markdown pipelines and sanitizer bypass (mXSS), prototype-pollution gadgets, postMessage, CSP/Trusted Types, and client-side template injection.

The repo ships two pieces:

- **Skill** (`skills/xss-audit/SKILL.md`): an AI agent runs the scan, reads each matching file, follows the value to its source, and decides whether it is a real finding.
- **Script** (`skills/xss-audit/scripts/scan.sh`): ripgrep patterns for each layer. It writes every match (a *lead*) to `xss-leads.tsv` and prints counts. It needs only `bash` and `rg`.

## Quick start

### 1. Install

Works with any agent (Claude Code, Cursor, Codex, Copilot, ...):

```bash
npx skills add Apaonum/xss-audit
```

Requires [ripgrep](https://github.com/BurntSushi/ripgrep): `brew install ripgrep`.

Claude Code plugin and manual install: see [Install](#install).

### 2. Run it

The skill is **user-invoked only**: the agent never starts it on its own, so you type it:

```
/xss-audit
```

To audit only part of a repo: `/xss-audit apps/web/src`. If you installed it as a Claude Code plugin, the command is `/xss-audit:xss-audit`.

### 3. Read the result

The agent works in four steps:

1. **Scope.** It records the audited root, the exclusions, and the frameworks and sanitizer versions.
2. **Scan.** `scan.sh` writes every lead to `xss-leads.tsv`.
3. **Trace.** For each lead, it reads the code, follows the value from source to sink, and marks the lead **Finding**, **Dismissed** (with a reason), or **Manual review**.
4. **Report.** It writes `xss-audit-report.md`. Every row of the coverage table must satisfy Leads = Findings + Dismissed + Manual review, so you can see that nothing was skipped.

Example: a small React component with a few common sinks.

```
$ bash skills/xss-audit/scripts/scan.sh src
Layer  Leads
L01    1
L02    1
L03    3
L04    1
L05    1
L06    2
L07    0
L08    1
...
L14    0
Leads written to xss-leads.tsv
```

<details>
<summary>The resulting finding in the report</summary>

```markdown
### 1. High · Preview · Unsanitized URL parameter in raw HTML

**Location**: `src/components/Preview.tsx:8` (layer L01)
**Data flow**: `window.location.search` → `URLSearchParams.get("html")` → `dangerouslySetInnerHTML`
**Source**: The `html` query parameter. The attacker sends the victim a crafted link.
**Sink**: React `dangerouslySetInnerHTML` on a `div` (HTML context).
**Missing defense**: No sanitizer between the parameter and the sink.
**Impact**: Script runs in the app's origin when the victim opens the link.
**Confidence**: High. The source and sink are in the same function.
**Reproduction**: Theoretical. `?html=<img src=x onerror=alert(document.domain)>`. Not executed.

**Fix**: Render `html` as text. If rich HTML is required, use `DOMPurify.sanitize(html)` as the last step before the sink.
```

The full template and a worked example are in [`references/report.md`](skills/xss-audit/references/report.md).

</details>

### Severity

| Severity | Meaning |
|---|---|
| High | Attacker input executes script in the app's origin when a victim loads a page or opens a link |
| Medium | Needs another victim action (e.g. clicking a `javascript:` link), a privileged or self-only attacker, or gets past a partial defense; or sensitive data sent with `postMessage(..., '*')` |
| Low | Hardening gap with no demonstrated path: no CSP, a permissive sanitizer config, a vulnerable sanitizer version with no reachable input |

## Run the script directly

```bash
bash skills/xss-audit/scripts/scan.sh [root] [out.tsv]
```

Each line of the output file is `LAYER<TAB>path:line:code`. Without the skill, you trace and dispose of the leads yourself; [`references/layers.md`](skills/xss-audit/references/layers.md) has the rules for each layer.

The scan excludes `node_modules`, `dist`, `build`, `.next`, `out`, `coverage`, minified files, source maps, and `.d.ts`.

## Install

### Any agent (Claude Code, Cursor, Codex, Copilot, ...) via the skills CLI

```bash
npx skills add Apaonum/xss-audit
```

### Claude Code plugin

```
/plugin marketplace add Apaonum/xss-audit
/plugin install xss-audit@xss-audit
```

To pick up new versions, run `/plugin marketplace update xss-audit`.

### Manual

```bash
git clone https://github.com/Apaonum/xss-audit
ln -s "$PWD/xss-audit/skills/xss-audit" ~/.claude/skills/xss-audit
```

## Layers

| Layer | Focus |
|---|---|
| L01 | HTML injection sinks: `innerHTML`, `dangerouslySetInnerHTML`, `DOMParser`, `setHTMLUnsafe` |
| L02 | Attribute and event-handler injection: `setAttribute`, `srcdoc`, `formaction` |
| L03 | URL and navigation sinks, and URL-validation bypasses (hostname-only, substring, `//`, backslash) |
| L04 | Config/content models and JSON-in-script (`</script>` breakout in SSR state and JSON-LD) |
| L05 | Props spreading and gadget components |
| L06 | Untrusted sources: URL, storage, cookies, postMessage (both directions) |
| L07 | Prototype pollution → XSS gadget |
| L08 | JS execution sinks: `eval`, `new Function`, string timers, workers |
| L09 | CSS / style injection |
| L10 | SVG / MathML |
| L11 | Markdown pipelines and sanitizers (mXSS, config, ordering, versions) |
| L12 | Framework raw-HTML hooks: `v-html`, `{@html}`, `unsafeHTML`, `bypassSecurityTrust*` |
| L13 | CSP and Trusted Types |
| L14 | Framework attribute binding and client-side template injection |

## Limits

- This is static analysis. It does not prove a codebase is free of XSS. Add dynamic testing, CSP, and Trusted Types.
- The patterns are a floor. The agent adds sinks it finds while tracing, but a sink hidden behind a third-party library or a generated name can still be missed.
- Some patterns (`href={…}`, `URLSearchParams`, `Object.assign(`) are noisy in large apps. That costs tracing time, not accuracy.
- Server-side template engines (Jinja, Razor, ERB) and backend code are out of scope.

## License

MIT
