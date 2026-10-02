// GitHub Pages 301-redirects '/blog' to '/blog/', so internal links use the slash form.
// External, protocol-relative, hash-only and file links ('/rss.xml') pass through untouched.
export function withSlash(href: string) {
  if (!href.startsWith('/') || href.startsWith('//')) return href
  const i = href.search(/[?#]/)
  const path = i === -1 ? href : href.slice(0, i)
  const rest = i === -1 ? '' : href.slice(i)
  if (path.endsWith('/') || /\.[a-z0-9]+$/i.test(path)) return href
  return `${path}/${rest}`
}
