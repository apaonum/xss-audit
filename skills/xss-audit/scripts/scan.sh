#!/usr/bin/env bash
# Usage: scan.sh [root] [out]
# Writes one lead per line to <out>: LAYER<TAB>path:line:code, and prints counts per layer.
set -euo pipefail

root="${1:-.}"
out="${2:-xss-leads.tsv}"
command -v rg >/dev/null || { echo "scan.sh: ripgrep (rg) is required" >&2; exit 1; }

globs=(
  -g '*.{js,jsx,ts,tsx,mjs,cjs,vue,svelte,astro,html,htm,hbs,ejs,css,scss,conf,toml}'
  -g 'package.json' -g 'vercel.json' -g '_headers'
  -g '!node_modules' -g '!dist' -g '!build' -g '!.next' -g '!out' -g '!coverage'
  -g '!*.min.*' -g '!*.map' -g '!*.d.ts'
)

: > "$out"
printf '%-6s %s\n' Layer Leads
# Patterns are a floor, not a ceiling: SKILL.md step 3 adds leads the agent finds while tracing.
while read -r layer pattern; do
  [[ -z "$layer" || "$layer" == \#* ]] && continue
  status=0
  matches=$(rg -n --no-heading --max-columns 300 --max-columns-preview "${globs[@]}" -e "$pattern" "$root") || status=$?
  (( status > 1 )) && { echo "scan.sh: rg failed on $layer" >&2; exit 1; }
  n=0
  if [[ -n "$matches" ]]; then
    printf '%s\n' "$matches" | awk -v l="$layer" '{print l "\t" $0}' >> "$out"
    n=$(printf '%s\n' "$matches" | wc -l | tr -d ' ')
  fi
  printf '%-6s %s\n' "$layer" "$n"
done <<'EOF'
L01 innerHTML|outerHTML|insertAdjacentHTML|document\.write|setHTMLUnsafe|attachShadow|dangerouslySetInnerHTML|DOMParser|parseFromString|createContextualFragment|cloneElement|createElement\(\s*[A-Za-z_$]
L02 setAttribute\(|srcDoc|srcdoc|formAction|formaction|\[\s*['"`]on[a-z]+['"`]\s*\]|\bon[a-z]+\s*=\s*['"]?\$\{
L03 window\.open\(|location(\.href)?\s*=[^=]|location\.(assign|replace)\(|history\.(pushState|replaceState)\(|router\.(push|replace)\(|\bnavigate\(|\bredirect\(|\b(href|src|action|formAction)=\{\s*[^'"`\s]|javascript:|new URL\(|\.hostname\b|startsWith\(\s*['"`]https?:|includes\(\s*['"`][\w.-]+\.[a-z]{2,}
L04 __INITIAL_STATE__|__NEXT_DATA__|__NUXT__|__APOLLO_STATE__|application/ld\+json|<script[^>]*>\s*\$\{|serialize-javascript|\b(linkExpression|htmlContent|rawHtml|richText|bodyHtml)\b
L05 \s\{\s*\.\.\.[A-Za-z_$][\w.]*\s*\}(\s|/?>|$)
L06 localStorage\.getItem|sessionStorage\.getItem|document\.cookie|indexedDB|URLSearchParams|useSearchParams|useParams|router\.query|location\.(search|hash)|document\.referrer|addEventListener\(\s*['"`]message|onmessage|postMessage\(|BroadcastChannel|MessageChannel
L07 __proto__|prototype\[|constructor\[|\b(merge|mergeWith|deepmerge|defaultsDeep|extend|setWith)\(|_\.set\(|Object\.assign\(
L08 \beval\(|new Function\(|[^.\w]Function\(|set(Timeout|Interval)\(\s*['"`]|importScripts\(|createObjectURL\(|new (Shared)?Worker\(|createElement\(\s*['"`]script
L09 cssText|style\.setProperty\(|insertRule\(|createGlobalStyle|expression\(|@import|url\(\s*['"]?\$\{|behavior:
L10 createElementNS|setAttributeNS|xlinkHref=\{|xlink:href=\{|foreignObject|annotation-xml|<math|\bon(begin|end|repeat)=|image/svg\+xml
L11 ['"`](marked|markdown-it|remark[\w-]*|rehype[\w-]*|showdown|dompurify|isomorphic-dompurify|sanitize-html|react-markdown|xss)['"`]|DOMPurify|sanitize\(|ALLOW_DATA_ATTR|ADD_TAGS|ADD_ATTR|ALLOWED_TAGS|ALLOWED_ATTR|allowedTags|allowedAttributes|allowedSchemes|allowDangerousHtml|skipHtml|html:\s*true
L12 v-html|bypassSecurityTrust|DomSanitizer|\{@html|unsafeHTML|unsafeSVG|\[innerHTML\]
L13 trustedTypes|require-trusted-types-for|Content-Security-Policy|contentSecurityPolicy|helmet\(|http-equiv
L14 data-bind|applyBindings|bindingHandlers|data-win-|WinJS|x-html|x-on:|x-bind:|x-data|x-init|ng-bind-html|\$sce\.trustAs|\$compile\(|\{\{\{|htmlSafe\(|SafeString\(|Vue\.compile\(|compileToFunctions|\btemplate:\s*[A-Za-z_$]
EOF
echo "Leads written to $out"
