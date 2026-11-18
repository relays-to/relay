# Documentation Instructions

Apply these rules to `docs`, `know_how`, `alternative_to`, and `legal`.

## Markdown docs apps

- Serve each area from one app with a `docs/` folder. Extend
  `MarkdownArticleMixin` from `abstract.views`.
- Keep slugs unique across docs apps. The template loader resolves
  `<slug>.md` against every TEMPLATES DIRS entry.
- Write relay-specific user docs in `docs/docs`.
- Every content Markdown file carries `modified_at: YYYY-MM-DD` in its front
  matter, interpreted as midnight UTC. Bump it in the same commit as any
  content change. Views and sitemaps use it for `Last-Modified`, ETag, and
  `lastmod`.
