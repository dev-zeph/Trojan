// Website test ids. AI-written nuclei templates are named after the site the
// model saw ("alphapets-loyalty-api-idor"), and nuclei reports that id as the
// finding's rule id. Every generated template gets trojan-custom-NNN instead, so
// a site's name never becomes a rule id (and the shared explanation cache, which
// rejects trojan-custom-*, never sees one). The CLI applies the same rewrite in
// internal/dast.SetTemplateID, so old clients and old cached rows are covered.
// This file has no imports and no side effects; dast-templates/index.ts only
// calls setTemplateIds.

// A top-level id key in block style, however it is written: id:, "id":, 'id':
// or id : (a top-level key starts in column 0). The line break goes with it.
const TOP_LEVEL_ID = /^(?:"id"|'id'|id)[ \t]*:[^\n]*(?:\n|$)/gm

const BOM = '\uFEFF'

/** True when the template's top level is a flow mapping ({id: x, ...}). */
export function isFlowStyleTemplate(template: string): boolean {
  for (const line of template.split('\n')) {
    const l = line.trim()
    if (l === '' || l.startsWith('#') || l === '---') continue
    return l.startsWith('{')
  }
  return false
}

/**
 * Set a template's top-level id to trojan-custom-NNN (n is 1-based). A leading
 * byte order mark is dropped, the first top-level id line is replaced, any
 * others are removed, and one is added when there is none. Returns null for a
 * flow-style template, whose id can't be rewritten safely without a YAML parser.
 */
export function setTemplateId(template: string, n: number): string | null {
  let t = template.startsWith(BOM) ? template.slice(1) : template
  if (isFlowStyleTemplate(t)) return null
  const id = `id: trojan-custom-${String(n).padStart(3, '0')}\n`
  let first = true
  t = t.replace(TOP_LEVEL_ID, () => {
    if (!first) return '' // a second top-level id would override the first
    first = false
    return id
  })
  if (!first) return t
  return t.startsWith('---\n') ? `---\n${id}${t.slice(4)}` : `${id}${t}`
}

/**
 * Renumber a list of templates trojan-custom-001, -002, ... in order. Flow-style
 * templates are dropped, and the rest are numbered without gaps.
 */
export function setTemplateIds(templates: string[]): string[] {
  const out: string[] = []
  for (const t of templates) {
    const fixed = setTemplateId(t, out.length + 1)
    if (fixed !== null) out.push(fixed)
  }
  return out
}
