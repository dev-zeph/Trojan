// Website test ids. AI-written nuclei templates are named after the site the
// model saw ("alphapets-loyalty-api-idor"), and nuclei reports that id as the
// finding's rule id. Every generated template gets trojan-custom-NNN instead, so
// a site's name never becomes a rule id (and the shared explanation cache, which
// rejects trojan-custom-*, never sees one). The CLI applies the same rewrite in
// internal/dast.SetTemplateID, so old clients and old cached rows are covered.
// This file has no imports and no side effects; dast-templates/index.ts only
// calls setTemplateIds.

// A top-level id key in block style, however it is written: id:, "id":, 'id':
// or id : (a top-level key starts in column 0). Group 1 is the value.
const TOP_LEVEL_ID_KEY = /^(?:"id"|'id'|id)[ \t]*:(.*)$/

const BOM = '\uFEFF'

/**
 * The template's first line that is not blank, a comment or a bare document
 * marker. A marker that shares its line with content ("--- {id: x}") gives
 * that content.
 */
export function firstContentLine(template: string): string {
  for (const raw of template.split('\n')) {
    let l = raw.replace(/\r$/, '')
    if (/^---(?:[ \t]|$)/.test(l)) l = l.slice(3).replace(/^[ \t]+/, '')
    const t = l.trim()
    if (t === '' || t.startsWith('#')) continue
    return l
  }
  return ''
}

/** True when the template's top level is a flow mapping ({id: x, ...}), also after a document marker (--- {id: x}). */
export function isFlowStyleTemplate(template: string): boolean {
  return firstContentLine(template).trim().startsWith('{')
}

/**
 * Why a template's id can't be rewritten safely without a YAML parser, or ''
 * when it can. Nuclei templates are plain block mappings, so these are
 * rejected rather than guessed at: flow style ({id: x}, --- {id: x}), an
 * indented top level ("  id: x"), explicit keys ("? id"), and an id with an
 * anchor or alias (id: &a x, id: *a).
 */
export function unsafeTemplate(template: string): string {
  const first = firstContentLine(template)
  if (first.trim().startsWith('{')) return 'flow style'
  if (first !== '' && (first[0] === ' ' || first[0] === '\t')) return 'indented top level'
  for (const raw of template.split('\n')) {
    const line = raw.replace(/\r$/, '')
    if (line === '?' || line.startsWith('? ') || line.startsWith('?\t')) return 'explicit key'
    const m = TOP_LEVEL_ID_KEY.exec(line)
    if (m) {
      const v = m[1].trim()
      if (v.startsWith('&') || v.startsWith('*')) return 'anchor or alias on id'
    }
  }
  return ''
}

/** True when a line starts with a space or tab and has content. */
export function isIndented(line: string): boolean {
  return (line.startsWith(' ') || line.startsWith('\t')) && line.trim() !== ''
}

/**
 * Set a template's top-level id to trojan-custom-NNN (n is 1-based). A leading
 * byte order mark is dropped, the first top-level id line is replaced, any
 * others are removed, and one is added when there is none. An id's value can
 * run onto indented lines (a block scalar such as "id: >-", or a plain value
 * that wraps); those lines go with it, so no part of the old id survives.
 * Returns null for a template unsafeTemplate rejects.
 */
export function setTemplateId(template: string, n: number): string | null {
  const t = template.startsWith(BOM) ? template.slice(1) : template
  if (unsafeTemplate(t) !== '') return null
  const id = `id: trojan-custom-${String(n).padStart(3, '0')}`
  const lines = t.split('\n')
  const kept: string[] = []
  let found = false
  for (let i = 0; i < lines.length; i++) {
    if (!TOP_LEVEL_ID_KEY.test(lines[i].replace(/\r$/, ''))) {
      kept.push(lines[i])
      continue
    }
    // Skip the value's continuation: indented lines, and blank lines followed
    // by more indented lines.
    let j = i + 1
    while (j < lines.length) {
      if (isIndented(lines[j])) {
        j++
        continue
      }
      if (lines[j].trim() === '') {
        let k = j
        while (k < lines.length && lines[k].trim() === '') k++
        if (k < lines.length && isIndented(lines[k])) {
          j = k
          continue
        }
      }
      break
    }
    if (!found) {
      kept.push(id) // the first id keeps its place
      found = true
    }
    i = j - 1
  }
  if (found) return kept.join('\n')
  return t.startsWith('---\n') ? `---\n${id}\n${t.slice(4)}` : `${id}\n${t}`
}

/**
 * Renumber a list of templates trojan-custom-001, -002, ... in order. Rejected
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
