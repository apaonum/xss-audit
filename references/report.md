# Report format

Follow the template below. The worked example after it shows the level of detail expected.

## Template

````markdown
# XSS Security Audit Report

**Date**: [YYYY-MM-DD]
**Scope**: [Audited roots; commit SHA if git]
**Exclusions**: [Path — reason, one per line]
**Stack**: [Frameworks; markdown renderer and sanitizer with resolved versions]
**Analysis Type**: Static, read-only. No dynamic verification.
**Leads file**: `xss-leads.tsv`

## Summary

| Findings | High | Medium | Low | Manual review |
|---|---|---|---|---|
| N | N | N | N | N |

## Findings

<!-- Sorted High → Low. "None." if empty. -->

### [N]. [Severity] · [Component/function] · [Vulnerability type]

**Location**: `path/to/file.tsx:123` (layer LNN)
**Data flow**: `source` → `step` → `sink`
**Source**: [What the attacker controls and how they deliver it]
**Sink**: [API and its context]
**Missing defense**: [What a defense that fits the context would be, and why the existing one fails]
**Impact**: [What executes or leaks, for which victim; any CSP that reduces it]
**Confidence**: [High / Medium / Low — what is established statically vs assumed]
**Reproduction**: Theoretical. [Payload and delivery. Not executed.]

```tsx
// vulnerable lines only
```

**Fix**: [Concrete change]

## Manual review

<!-- One entry per lead: location, layer, what blocks a static verdict, what to check. "None." if empty. -->

## Dismissed leads

<!-- Group identical reasons; list every location. -->

| Layer | Locations | Reason |
|---|---|---|

## Coverage

Leads = Findings + Dismissed + Manual review for every row. The one exception is a "no CSP" finding in L13, which has no lead.

| Layer | Focus | Leads | Findings | Dismissed | Manual review |
|---|---|---|---|---|---|
| L01 | HTML sinks | | | | |
| L02 | Attribute/event sinks | | | | |
| L03 | URL/navigation | | | | |
| L04 | Content models & JSON-in-script | | | | |
| L05 | Props spreading | | | | |
| L06 | Untrusted sources & postMessage | | | | |
| L07 | Prototype pollution | | | | |
| L08 | JS execution sinks | | | | |
| L09 | CSS/style | | | | |
| L10 | SVG/MathML | | | | |
| L11 | Markdown & sanitizers (mXSS) | | | | |
| L12 | Framework raw-HTML hooks | | | | |
| L13 | CSP & Trusted Types | | | | |
| L14 | Binding & template injection | | | | |
````

## Worked example

Fictional: `example-react-app`, `src/` only. No real repository was scanned.

````markdown
# XSS Security Audit Report

**Date**: 2026-10-30
**Scope**: `src/`
**Exclusions**: `node_modules/` — dependencies; `dist/` — build output
**Stack**: React 18.3.1; dompurify 3.2.4
**Analysis Type**: Static, read-only. No dynamic verification.
**Leads file**: `xss-leads.tsv`

## Summary

| Findings | High | Medium | Low | Manual review |
|---|---|---|---|---|
| 2 | 1 | 0 | 1 | 0 |

## Findings

### 1. High · Preview · Unsanitized URL parameter in raw HTML

**Location**: `src/components/Preview.tsx:8` (layer L01)
**Data flow**: `window.location.search` → `URLSearchParams.get("html")` → `dangerouslySetInnerHTML`
**Source**: The `html` query parameter. The attacker sends the victim a crafted link.
**Sink**: React `dangerouslySetInnerHTML` on a `div` (HTML context).
**Missing defense**: No sanitizer between the parameter and the sink. DOMPurify is installed but not used on this path.
**Impact**: Script runs in the app's origin when the victim opens the link. No CSP is present (finding 2).
**Confidence**: High. The source and sink are in the same function.
**Reproduction**: Theoretical. `?html=<img src=x onerror=alert(document.domain)>`. Not executed.

```tsx
const html = new URLSearchParams(window.location.search).get("html") ?? "";
return <div dangerouslySetInnerHTML={{ __html: html }} />;
```

**Fix**: Render `html` as text. If rich HTML is required, use `DOMPurify.sanitize(html)` as the last step before the sink.

### 2. Low · App shell · No Content-Security-Policy

**Location**: none. L13 had 0 leads; no CSP in headers, config, or meta tags.
**Impact**: Nothing limits the impact of finding 1 or of future injection bugs.
**Fix**: Add a CSP with nonce-based `script-src`. Consider `require-trusted-types-for 'script'`.

## Manual review

None.

## Dismissed leads

| Layer | Locations | Reason |
|---|---|---|
| L03 | `src/nav/Links.tsx:12`, `:18`, `:24` | `href` takes hard-coded route constants |
| L06 | `src/components/Preview.tsx:7` | Source of finding 1; recorded there |
| L11 | `src/lib/sanitize.ts:3` | DOMPurify import; no sink uses it (see finding 1) |

## Coverage

| Layer | Focus | Leads | Findings | Dismissed | Manual review |
|---|---|---|---|---|---|
| L01 | HTML sinks | 1 | 1 | 0 | 0 |
| L03 | URL/navigation | 3 | 0 | 3 | 0 |
| L06 | Untrusted sources & postMessage | 1 | 0 | 1 | 0 |
| L11 | Markdown & sanitizers (mXSS) | 1 | 0 | 1 | 0 |
| L13 | CSP & Trusted Types | 0 | 1 | 0 | 0 |
| Others | — | 0 | 0 | 0 | 0 |
````
