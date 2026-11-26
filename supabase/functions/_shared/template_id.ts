// Website test ids. AI-written nuclei templates are named after the site the
// model saw ("alphapets-loyalty-api-idor"), and nuclei reports that id as the
// finding's rule id. Every generated template gets trojan-custom-NNN instead, so
// a site's name never becomes a rule id (and the shared explanation cache, which
// rejects trojan-custom-*, never sees one). The CLI applies the same rewrite in
// internal/dast.SetTemplateID, so old clients and old cached rows are covered.

const TOP_LEVEL_ID = /^id:[^\n]*$/m

/** Set a template's top-level id to trojan-custom-NNN (n is 1-based). */
export function setTemplateId(template: string, n: number): string {
  const id = `id: trojan-custom-${String(n).padStart(3, '0')}`
  return TOP_LEVEL_ID.test(template) ? template.replace(TOP_LEVEL_ID, id) : `${id}\n${template}`
}

/** Renumber a list of templates trojan-custom-001, -002, ... in order. */
export function setTemplateIds(templates: string[]): string[] {
  return templates.map((t, i) => setTemplateId(t, i + 1))
}
