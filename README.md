# xss-audit

A Claude Code skill that runs a read-only, static XSS audit of a frontend codebase. It searches 14 sink/source layers (HTML, attribute, URL, JS, and CSS sinks; JSON-in-script; mXSS; framework template injection) and writes `xss-audit-report.md`.

## Install

```bash
git clone https://github.com/Apaonum/xss-audit.git ~/.claude/skills/xss-audit
```

Requires [ripgrep](https://github.com/BurntSushi/ripgrep) (`brew install ripgrep`).

## Use

In the repo you want to audit, type `/xss-audit`. The skill is user-invoked only; Claude will not start it on its own.

The audit has four steps:

1. Scope the audit.
2. `scripts/scan.sh` writes every pattern match (a *lead*) to `xss-leads.tsv`.
3. The agent traces each lead from source to sink and marks it Finding, Dismissed, or Manual review.
4. The agent writes the report. Its coverage table must account for every lead.

## Layout

| Path | Purpose |
|---|---|
| `SKILL.md` | Vocabulary, severity rubric, steps |
| `scripts/scan.sh` | ripgrep patterns for each layer |
| `references/layers.md` | Rules for each layer, read only for layers that have leads |
| `references/report.md` | Report template and worked example |

Static analysis cannot prove a codebase is free of XSS. Add dynamic testing, CSP, and Trusted Types alongside it.
