---
name: Domain check
description: What the public domain check grades, how the S to F tier is earned, and when a check runs
author: Johannes Maron
---

# Domain check

The domain check grades the email configuration of any public domain and
publishes the result as a tier from S to F. It is free and needs no account.
Enter a domain on
<a href="{% url 'domain_check:list' %}">the domain check</a>, and relay reads
the records a receiving mail server reads, fetches the MTA-STS policy, queries
blocklists, and reports every finding with the fix. Results are public, so a
grade is a link you can share.

The check answers one question: if a receiver inspected this domain today,
what would it find? The tier describes the configuration relay can see from
the outside. It is not a promise of inbox placement.

## What the check runs

See which rows the check runs. Six rows appear on a completed check. Each
row covers one part of the record set that decides whether a receiver
accepts, encrypts, and reports on the mail.

| Row        | What relay reads                                   | What the row grades                                       |
| ---------- | -------------------------------------------------- | --------------------------------------------------------- |
| MX         | MX records at the domain root                      | Routing and record TTL                                    |
| SPF        | TXT at the domain root                             | Authorization, lookup budget, qualifier, reverse DNS, TTL |
| DMARC      | TXT at `_dmarc.<domain>`                           | Policy, reporting, coverage, TTL                          |
| MTA-STS    | TXT at `_mta-sts.<domain>` and the policy document | Fetch, mode, MX match, TTL                                |
| TLS-RPT    | TXT at `_smtp._tls.<domain>`                       | Reporting address, TTL                                    |
| Blocklists | Spamhaus DBL and address blocklists                | Domain and SPF address listings                           |

The check reads public DNS. For MTA-STS it also fetches one HTTPS document,
the policy, and checks the MX records against it. No message is sent.

## What each row grades

Learn how each row grades. A resolver failure skips the line. A missing
record fails it. The severity of that failure decides the tier.

### MX

Learn whether mail can reach the domain. relay resolves the MX records at
the root. A null MX record (`0 .`) passes because the domain declares that
it receives no mail. A missing record is a blocking failure: mail cannot
route. A published record passes and lists up to five exchanges.

The row also grades the record TTL, read from the authoritative nameserver.
At least one hour passes, with five minutes of tolerance for resolver
countdown. A shorter TTL is a weak failure.

### SPF

Learn which servers may send for the domain. relay needs exactly one
`v=spf1` TXT record at the root. No SPF record and more than one SPF record
are blocking failures; receivers treat a duplicate as a permanent error.

relay walks the record the way a receiver walks it. Every `include`, `a`,
`mx`, `ptr`, `exists`, and `redirect` term counts as one DNS lookup, and the
record may need at most ten. A record over the budget is a blocking failure.
The `all` mechanism should carry the `-` qualifier: `-all` passes, and any
other qualifier or a missing `all` is a weak failure.

The record TTL follows the same one-hour minimum as MX. A shorter TTL is a
weak failure.

#### Reverse DNS

Read the PTR record of every exact public address the SPF record
authorizes. A literal `ip4:` or `ip6:` address and an `a` or `mx` host
without a prefix are exact. The name must resolve back to the same address.
A mismatch is a weak failure, and the row lists the addresses that fail.
When the record covers only network ranges, the line is skipped. When no
PTR query answers, the line is skipped instead of failed.

### DMARC

Learn whether the domain tells receivers what to do with unauthenticated
mail. relay needs exactly one `v=DMARC1` TXT record at `_dmarc.<domain>`. A
missing record, a duplicate record, or a `p` tag outside `none`,
`quarantine`, and `reject` is a blocking failure.

The policy is then graded on three points:

- `p=reject` passes. `p=quarantine` and `p=none` are weak failures.
- An `rua=` address passes. Without one, the row is a weak failure, because
  aggregate reports have nowhere to go.
- `pct=100` passes. A lower `pct` is a weak failure, and an absent `pct`
  counts as 100.

The record TTL follows the one-hour minimum. A shorter TTL is a weak
failure.

### MTA-STS

Learn whether the domain publishes a policy that receivers can enforce.
relay needs a `v=STSv1` TXT record with an `id` at `_mta-sts.<domain>`. A
missing or malformed record is a broken failure.

relay then fetches `https://mta-sts.<domain>/.well-known/mta-sts.txt`. The
fetch accepts HTTPS only, connects to a public address, follows no redirects,
gives up after five seconds or 64 KiB, and reuses a fetched body for five
minutes. A policy that does not fetch or parse is a broken failure. The
policy needs `version: STSv1`, a positive `max_age`, at least one `mx`, and
a mode of `enforce`, `testing`, or `none`.

The fetched policy is then graded on two points:

- `mode: enforce` passes. `testing` and `none` are weak failures.
- Every live MX host must match an `mx` pattern. `*` matches any host, and
  `*.example.com` matches one label under `example.com`. A host outside the
  policy is a broken failure. A domain with no live MX host fails this line
  too.

The record TTL follows the one-hour minimum. A shorter TTL is a weak
failure.

### TLS-RPT

Learn whether the domain collects TLS reports. relay needs a `v=TLSRPTv1`
TXT record at `_smtp._tls.<domain>`. A missing record is a broken failure.
The record must carry an `rua=` value; without one, the row is a broken
failure.

The record TTL follows the one-hour minimum. A shorter TTL is a weak
failure.

### Blocklists

Learn whether the domain or its senders are already listed. relay queries
the domain on Spamhaus DBL and each SPF address on Spamhaus ZEN and
SpamCop. Network ranges in SPF are sampled at the first host, and private
or transition addresses are ignored. A listing on any list is a blocking
failure, because receivers drop or quarantine mail from a listed source.

When a blocklist refuses the query or does not answer, the row names the
unavailable list and skips that provider. If every provider is unavailable,
the line is not checked rather than failed. A check with no SPF address
skips the address line.

## How the tier is earned

Learn what moves the grade. A completed check starts at S. A skipped line
costs nothing. A weak failure adds one penalty point, and a broken failure
adds two. A blocking failure pins the result to F, whatever else failed.
Count the penalty down this ladder:

| Penalty points | Tier |
| -------------- | ---- |
| 0              | S    |
| 1              | A+   |
| 2              | A    |
| 3              | A-   |
| 4              | B    |
| 5              | B-   |
| 6              | C    |
| 7              | C-   |
| 8              | D    |
| 9              | D-   |
| 10             | E    |
| 11             | E-   |
| 12 or more     | F    |

A weak failure moves one step down the ladder, for example S to A+. A
broken failure moves two steps, for example S to A. A blocking failure is F
even when every other line passes.

## How to read a result

Learn what each element on the result page reports. For a completed check,
the result page shows the domain, the time of the last check, and the tier
badge. The share button copies the result link and opens the system share
sheet when available. The recheck button starts a new check.

Each of the six rows shows:

- the row name,
- a status badge: pass, partial, or fail,
- the number of issues, when it has any.

A row reads pass when at least one line passes and no line fails. It reads
partial when a line fails weakly, or when every line is skipped. It reads
fail when a line fails as broken or blocking. The issue count includes
every line that is neither pass nor skip, so a skipped line never counts as
an issue.

The row body lists the subchecks. Each line carries a label, the measured
value, and one of these marks:

| Mark           | Meaning                    | Cost              |
| -------------- | -------------------------- | ----------------- |
| Green check    | Pass                       | None              |
| Amber triangle | Weak failure               | Half a tier       |
| Red cross      | Broken or blocking failure | A full tier, or F |
| Dashed circle  | Skipped                    | None              |

A failing line carries a `Fix:` hint. A row with a knowledge page carries a
`Learn more` link. A reverse-DNS finding lists the affected addresses, and
each address opens the network behind it, with a map when available. Rows
that are not pass open by default.

The index lists every domain checked so far, with its state, the time of
its last check, and its tier once complete. A shared result carries a card
with the domain and, once the check completes, its tier.

## When a check runs

Learn how fresh a result is and how to refresh it. A new domain starts a
check immediately. A completed result is reused for a day. The list form
starts a check only when the stored result is stale: older than a day, or
failed. Inside that window it shows the stored result and says so.

The recheck button on a result page runs a fresh check at any time,
including inside the daily window. While a check is pending or running, the
page shows the progress state and refreshes until the six rows are stored.
A recheck during that window does nothing.

relay splits the six rows across three jobs that run in parallel: delivery
for MX, MTA-STS, and TLS-RPT; authentication for SPF and DMARC; and
reputation for blocklists. The result becomes complete only when all six
rows are stored, so a partial set never gets a grade. Each of the three jobs
retries twice before the check is marked failed. relay does not refresh a
stored result in the background; it stays as it was until someone asks
again after the day or presses recheck.

## What the check does not do

Know the limits of the grade. The check reads public DNS and one HTTPS
policy document. It does not send a message, so it does not prove delivery
or inbox placement. It does not grade DKIM selectors or signatures; a
receiver learns those from signed mail. It does not audit message content,
complaint rates, or bounce handling.

## Related pages

- <a href="{% url 'docs:detail' slug='deliverability' %}">Deliverability</a>.
  The records a receiver reads and what each one proves.
- <a href="{% url 'docs:detail' slug='domains' %}">Managed domains and DNS</a>.
  The records relay serves for a delegated domain.
- <a href="{% url 'docs:detail' slug='reputation' %}">Sender reputation</a>.
  The signals beyond the records.
