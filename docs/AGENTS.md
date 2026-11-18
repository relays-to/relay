# Documentation Instructions

Apply these rules to `docs`, `know_how`, `alternative_to`, and `legal`.

## Audience

`docs/docs` serves relay users. Users integrate relay or run it for their
organization. A reader must be able to do a task or make a decision after
each article.

Write usage instructions, not implementation notes. Describe what the user
does, what relay shows, and what the user must do next.

Keep these details:

- Screen names, buttons, and navigation paths.
- Values the user copies: hosts, ports, DNS records, headers, and payloads.
- Behavior the user observes: statuses, replies, retries, limits, and errors.
- Protocol facts that change a user action. Link the background in
  `know_how`.

Remove these details:

- Internal services, queues, workers, storage, and deployment.
- Code paths, class names, migrations, and test behavior.
- Platform threat models, accepted risks, and security review notes.
- Architecture facts that do not change what the user does.

If a fact only helps a maintainer, remove it or put it in `AGENTS.md`. Never
put it in `docs/docs`.

## Writing

- Write to the reader as "you".
- Use the active voice and the simple present.
- Start a procedure with the result. Then give the steps.
- Put a condition before the command. Write "If the record is missing, add
  it."
- Keep one term for one concept.
- Write short sentences. Split a sentence that carries two instructions.
- Do not use em dashes or semicolons. Quoted records and code are the
  exception.
- Use a table for statuses, limits, records, errors, and reply codes.
- Use a troubleshooting table at the end of setup articles.
- Keep frontmatter `name`, `description`, and `author`.
- Link related articles with `{% url 'docs:detail' slug='...' %}`.
- Link protocol background with `{% url 'know_how:detail' slug='...' %}`.

## Markdown docs apps

- Serve each area from one app with a `docs/` folder. Extend
  `MarkdownArticleMixin` from `abstract.views`.
- Keep slugs unique across docs apps. The template loader resolves
  `<slug>.md` against every TEMPLATES DIRS entry.
- Write relay-specific user docs in `docs/docs`.
- Do not add a Markdown file to `docs/docs` unless it is a user article.
  The content index publishes every `.md` file.
