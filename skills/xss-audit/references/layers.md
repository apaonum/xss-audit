# Layers

Read only the sections for layers that have leads. Each section covers what its leads catch, the traps that make a lead look safe when it is not, and when a lead becomes a finding.

## L01 · HTML injection sinks (HTML context)

`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `setHTMLUnsafe`, `ShadowRoot.innerHTML`, `dangerouslySetInnerHTML`, `DOMParser`, `createContextualFragment`, plus `createElement`/`cloneElement` with a dynamic tag or props.

- A finding needs untrusted HTML that reaches the sink without a maintained sanitizer. Verify the sanitizer and its config under L11.
- If the value is plain text, the fix is to stop using the HTML sink (`textContent`, or JSX text). Mention this in the recommendation.

## L02 · Attribute and event-handler injection (attribute/JS context)

`setAttribute`, `srcdoc`, `formaction`, dynamic attribute names, `on*` handlers built from strings.

- `setAttribute('on…', x)`, or an attacker-chosen attribute name, is JS context: any untrusted input is a finding.
- `setAttribute('href'|'src'|'action', x)` is URL context: apply the L03 rules.
- `srcdoc` is HTML context: apply the L01 rules. Also check the `sandbox` attribute: `allow-scripts allow-same-origin` on same-origin content lets the frame remove its own sandbox.

## L03 · URL injection and navigation (URL context)

Sinks: `href`/`src`/`action`/`formAction` props, `window.open`, `location =`, `location.assign/replace`, router `push/replace/navigate`, and server `redirect`.

`history.pushState/replaceState` does not load the URL. Trace whoever reads the changed URL afterwards; the call alone is never a finding.

**Validation traps.** Check every validator on the path against each of these:
1. **Hostname-only check.** `new URL('javascript://trusted.com/%0aalert(1)').hostname` is `trusted.com`. A navigation sink also needs a protocol check.
2. **Substring or prefix check.** `includes('trusted.com')` and `startsWith('https://trusted.com')` let `https://trusted.com.evil.com`, `https://trusted.com@evil.com`, and `https://evil.com/?q=trusted.com` through.
3. **Raw-string comparison.** Case, leading whitespace, and control characters are normalized by the parser but not by a string comparison.
4. **Protocol-relative URL.** `//evil.com` passes a naive "starts with `/`" check.
5. **Backslash.** Browsers treat `https:\\evil.com` as `https://evil.com`, while string checks do not.

**A defense that fits the context** parses with `new URL(input, fixedTrustedBase)`, applies a protocol allowlist chosen for the element (commonly `http:`/`https:`; `mailto:`/`tel:`/relative URLs only when intended), and compares the hostname exactly or as a dot-boundary suffix.

**Severity.** `javascript:` in `href` needs a click, so it is usually Medium. In `location`, `window.open`, or an auto-submitted form it is High.

## L04 · Config/content models and JSON-in-script

- **Inline script data.** Leads in SSR bootstrap (`__NEXT_DATA__`, `__INITIAL_STATE__`, `__NUXT__`, `__APOLLO_STATE__`), hydration data, and JSON-LD.
  - `JSON.stringify` does not neutralize `</script>`. An attacker-influenced string inside an inline `<script>` without `<` escaped as `<` is a finding.
  - These are safe: `.replace(/</g, '\\u003c')`, `serialize-javascript`, and the framework's own serializer for its own bootstrap (e.g. Next.js `__NEXT_DATA__`).
  - Hand-written JSON-LD via `dangerouslySetInnerHTML` is the most common real finding here.
- **Content models.** For CMS/config objects with `url`/`href`/`html`/`template` fields, find where each field is rendered and apply the rules of that sink's layer.

## L05 · Props spreading and gadget components

`{...props}` on `<a>`, `<iframe>`, `<form>`, or a link/router component. It is a finding only if attacker-shaped data reaches the spread object and can set `href`, `src`, `srcDoc`, `dangerouslySetInnerHTML`, or `on*`. Spreading props the component author wrote is dismissed.

## L06 · Untrusted sources

These leads are sources. Trace each one forward to a sink in another layer, and record the disposition under the layer of the sink. Dismiss it here if the value never reaches a sink.

- **postMessage receiver.** It needs an exact `event.origin` allowlist and validation of the message schema, plus an `event.source` check when the sender window matters. A missing origin check that feeds a sink is a finding under that sink's layer.
- **postMessage sender.** `postMessage(data, '*')` delivers to whatever origin the target window currently holds. It is a finding (Medium) only if the payload is sensitive (tokens, PII) and the target window can be navigated by an attacker.

## L07 · Prototype pollution → XSS gadget

`merge`/`deepmerge`/`defaultsDeep`/`set` on attacker-shaped JSON, and `__proto__`/`constructor`/`prototype` keys. A finding needs all three of: an attacker-controlled pollution path, the polluted object, and a reachable gadget that reads the polluted property into a sink (e.g. a sanitizer's config or a component's `dangerouslySetInnerHTML`). Without a gadget, the lead goes to Manual review.

## L08 · JS execution sinks (JS context)

`eval`, `new Function`, `setTimeout`/`setInterval` with a string, `importScripts`, `Worker`/`createObjectURL` running generated code, and `createElement('script')` with a dynamic `src` or text. Any attacker influence is High. Recommend removing the sink.

## L09 · CSS / style injection (CSS context)

`cssText`, `setProperty`, `insertRule`, `createGlobalStyle`, `url(${…})`, `@import`.

- Modern CSS does not execute JS. Its impact is data exfiltration (attribute selectors with `url()`), UI redress, and outbound requests, so it is usually Medium or Low.
- `expression()`/`behavior:` matter only if the supported browsers include legacy IE.
- Also check CSS-in-JS interpolations fed by L06 sources even when no lead points there.

## L10 · SVG / MathML

`createElementNS`, `setAttributeNS`, dynamic `xlink:href`, `foreignObject`, `annotation-xml`, SVG animation events, and SVG served or uploaded as `image/svg+xml`.

- A user-uploaded SVG served from the app's origin and opened directly is a stored-XSS finding.
- An SVG rendered via `<img>` is dismissed.
- Pass namespace-confusion primitives to the L11 mXSS check.

## L11 · Markdown pipelines and sanitizers (mXSS)

**Pipeline.** Map the full chain: user input → markdown renderer → sanitizer → DOM. Check each item:

1. **Version.** Compare the resolved lockfile version of DOMPurify / sanitize-html / the renderer against known advisories. Being "latest at some point" is not evidence of safety.
2. **Config.** Look at `ADD_TAGS`/`ADD_ATTR`/`ALLOWED_TAGS` that admit `svg`, `math`, `style`, `iframe`, or `on*`; at `allowDangerousHtml` and `rehype-raw` without `rehype-sanitize`; and at `html: true` in markdown-it. Record the effective allowlist.
3. **Order.** Sanitizing must be the last step before insertion. `el.innerHTML = sanitize(a) + b`, or sanitizing followed by string replacement or markdown post-processing, invalidates the sanitizer.
4. **Double parse.** Sanitized output that passes through `DOMParser`, `template.innerHTML`, or `createContextualFragment` and is then serialized and re-inserted is an mXSS risk. The classic vector is namespace confusion: `<math><mtext><table><mglyph><style><!--</style><img onerror=…>`.
5. **Wrong context.** HTML-sanitizer output placed into an attribute, a JS string, or inside `<svg>`/`<math>`.

`ALLOW_DATA_ATTR` (on by default in DOMPurify) matters only if an L14 binding chain exists.

## L12 · Framework raw-HTML hooks

| Construct | Behaviour |
|---|---|
| Vue `v-html` | Raw HTML |
| Svelte `{@html}` | Raw HTML |
| Lit `unsafeHTML`/`unsafeSVG` | Raw HTML |
| Angular `bypassSecurityTrust*` | Raw HTML |
| Angular `[innerHTML]` | Sanitized by Angular, so dismiss unless it is combined with a bypass |

Normal text interpolation in each framework is escaped.

## L13 · CSP and Trusted Types (hardening)

- Record the effective CSP: where it is set (headers, `next.config.js`, meta tag), `script-src` (look for `'unsafe-inline'`, `'unsafe-eval'`, wildcard hosts), and whether `require-trusted-types-for 'script'` is present.
- If no CSP exists anywhere, report one Low finding.
- Use the CSP to adjust the impact of other findings; it never dismisses them.

## L14 · Framework attribute binding and client-side template injection

Some frameworks evaluate attribute values or template source as code. The attribute families differ:
- Knockout `data-bind` and WinJS `data-win-*` are `data-*`, so DOMPurify's `ALLOW_DATA_ATTR` lets them through.
- Alpine `x-*` and AngularJS `ng-*` are not `data-*`, so that setting does not affect them.

**Knockout chain** (the reference case): untrusted HTML containing `<div data-bind="text: (alert(document.domain),'')">` → the sanitizer keeps `data-bind` → the node is inserted inside a root that a later `ko.applyBindings`/`applyBindingsToDescendants` traverses → Knockout evaluates the expression.

**Template injection.** Attacker-controlled template *source* compiled by AngularJS, `Vue.compile`/the runtime compiler, Angular JIT, Handlebars, or a similar engine. Escaped interpolation of a value into a fixed template is not template injection.

**A finding needs all of:**
1. The exact construct survives the sanitizer (check the effective output, not just the flag).
2. The node sits inside a binding or compile root that runs after insertion.
3. The framework actually traverses it, i.e. `controlsDescendantBindings`, custom bindings, and skip rules do not stop it.
4. The expression can reach something security-sensitive.

Record the framework and version in the finding.
