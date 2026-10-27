import yaml from 'js-yaml'

/**
 * Profile name for pasted share links, taken from the converted config: the
 * node's own name, or the first name plus how many more were pasted
 * (`🇩🇪 MAX ~ DE +12`). Falls back to `fallback` when no name is found.
 */
export const profileNameFromConfig = (
  config: string,
  fallback: string,
): string => {
  try {
    const doc = yaml.load(config) as { proxies?: { name?: unknown }[] } | null
    const names = (doc?.proxies ?? [])
      .map((proxy) => proxy?.name)
      .filter(
        (name): name is string =>
          typeof name === 'string' && name.trim() !== '',
      )
    if (names.length === 0) return fallback
    return names.length === 1 ? names[0] : `${names[0]} +${names.length - 1}`
  } catch {
    return fallback
  }
}
