---
name: xss-audit
description: Read-only static XSS audit of a frontend codebase across 14 sink/source layers; writes xss-audit-report.md.
disable-model-invocation: true
---

# XSS audit

A static, **read-only** audit. The only files you write are `xss-leads.tsv` and the report.

## Vocabulary

- **Lead**: one line that `scan.sh` matched. A lead tells you where to look. It is never a result by itself.
- **Context**: the parser that consumes the value at the sink: HTML, attribute, URL, JS, or CSS. A defense counts only if it fits the sink's context. For example, HTML escaping does not protect a URL, a hostname check does not protect a navigation, and `JSON.stringify` does not protect a `<script>` body.
- **Finding**: a lead with a complete path: an attacker-controlled **source**, then its transformations, then the **sink**, where the defense for that context is missing or can be bypassed.
- **Disposition**: every lead ends as exactly one of:
  - **Finding**
  - **Dismissed**, with a one-line reason (static value, trusted source, or a defense that fits the context, named)
  - **Manual review**, stating what blocks a static verdict

## Severity

| Severity | Criterion |
|---|---|
| High | Attacker-controlled input executes script in the app's origin when a victim loads a page or opens a link: reflected, stored, or DOM XSS, or a JS execution sink. |
| Medium | Execution needs another victim action (e.g. clicking an attacker-supplied `javascript:` link), a privileged or self-only attacker, or gets past a partial defense. Also: sensitive data sent with `postMessage(..., '*')` to a window an attacker can control. |
| Low | A hardening gap with no demonstrated path: missing CSP or Trusted Types, a permissive sanitizer config, or a vulnerable sanitizer version with no reachable input. |

A CSP you have verified reduces impact. Record it in the finding; it does not remove the finding.

## Steps

1. **Scope.** Choose the root(s) to audit. Record the exclusions: dependencies, generated or minified output, and anything else you skip, each with a reason. From `package.json` and the lockfile, record the frameworks and the resolved versions of the markdown renderer and sanitizer. *Done when* the report's Scope, Exclusions, and Stack lines are drafted.
2. **Scan.** Run `bash <this-skill-dir>/scripts/scan.sh <root> xss-leads.tsv`. *Done when* it prints the lead count for each layer. If `rg` is missing, stop and tell the user.
3. **Trace.** For each layer that has leads:
   - Read that layer's section in [`references/layers.md`](references/layers.md).
   - For every lead, read the enclosing function, follow the value back to its source and forward to its sink, and assign a disposition. Follow the value across files when it crosses them.
   - You may dispose of identical leads as a group (e.g. 40 `href={...}` that all take hard-coded route constants). Each one still counts.
   - The scan is a floor, not a ceiling. If tracing uncovers a sink the patterns missed, add it as a lead under its layer and trace its call sites too. A typical case is a wrapper component that forwards a prop into `dangerouslySetInnerHTML`.

   *Done when* every line in `xss-leads.tsv`, plus every added lead, has a disposition.
4. **Report.** Write `xss-audit-report.md` following [`references/report.md`](references/report.md). If that file already exists, write `xss-audit-report-YYYYMMDD-HHMM.md` instead. *Done when* every row of the layer table satisfies Leads = Findings + Dismissed + Manual review (the only exception is a "no CSP" finding, which has no lead), and the Leads column equals the scan count plus the leads you added.
