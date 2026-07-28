import yaml from 'js-yaml'

/**
 * Split-routing presets applied to the Global Extend Config (the "Merge" file).
 *
 * The Merge file is used rather than a profile's rules enhancement because it
 * accepts both `prepend-rules` and `rule-providers` in one document, so a
 * preset can be applied atomically. Rules land in `prepend-rules`, which mihomo
 * evaluates *above* the profile's own rules, so the preset wins and survives
 * subscription updates and profile switches.
 */

/** Routes Iranian traffic DIRECT using only the geo data bundled with the app. */
export const IRAN_OFFLINE_RULES = [
  // Broad TLD match first: the bundled `category-ir` list is small, so this
  // covers the Iranian sites it does not know about.
  'DOMAIN-SUFFIX,ir,DIRECT',
  // Known Iranian sites that do not use a .ir domain.
  'GEOSITE,category-ir,DIRECT',
  // Anything served from an Iranian IP range.
  'GEOIP,IR,DIRECT,no-resolve',
] as const

export const IRAN_PROVIDER_NAME = 'iran_domains'

/**
 * Larger Iranian domain list, fetched at runtime. Published as a Clash
 * rule-provider payload, which mihomo consumes directly.
 */
export const IRAN_PROVIDER = {
  type: 'http',
  behavior: 'domain',
  format: 'yaml',
  interval: 86400,
  url: 'https://github.com/bootmortis/iran-hosted-domains/releases/latest/download/clash_rules_other.yaml',
  path: './ruleset/iran_domains.yaml',
} as const

const PROVIDER_RULE = `RULE-SET,${IRAN_PROVIDER_NAME},DIRECT`

type MergeDoc = Record<string, unknown>

const parseMerge = (text: string): MergeDoc => {
  if (!text.trim()) return {}
  const parsed = yaml.load(text)
  // A Merge file containing only comments parses to null/undefined.
  return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
    ? (parsed as MergeDoc)
    : {}
}

const asStringList = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((v): v is string => typeof v === 'string')
    : []

/**
 * Adds the Iran split-routing rules to a Merge document.
 *
 * Preset rules are placed above any existing `prepend-rules` so they are
 * matched first. Applying twice is a no-op: rules already present are not
 * duplicated, they are only moved to the front.
 *
 * @param mergeText current Merge file contents (may be empty or comment-only)
 * @param online    also register the online rule-provider for wider coverage
 */
export const applyIranPreset = (
  mergeText: string,
  { online }: { online: boolean },
): string => {
  const doc = parseMerge(mergeText)

  const presetRules: string[] = [...IRAN_OFFLINE_RULES]
  if (online) {
    // Checked before the bundled rules: it is the most specific list.
    presetRules.unshift(PROVIDER_RULE)

    const providers =
      doc['rule-providers'] && typeof doc['rule-providers'] === 'object'
        ? (doc['rule-providers'] as Record<string, unknown>)
        : {}
    doc['rule-providers'] = {
      ...providers,
      [IRAN_PROVIDER_NAME]: IRAN_PROVIDER,
    }
  }

  const existing = asStringList(doc['prepend-rules'])
  doc['prepend-rules'] = [
    ...presetRules,
    ...existing.filter((rule) => !presetRules.includes(rule)),
  ]

  return yaml.dump(doc, { lineWidth: -1, noRefs: true })
}
