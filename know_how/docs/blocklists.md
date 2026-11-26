---
name: Blocklists
description: DNS lists that mark domains and IP addresses as spam sources
author: Johannes Maron
modified_at: 2026-11-26
---

# Blocklists

> **TL;DR**: Blocklists name domains and IP addresses that sent spam. Receiving mail servers query them and reject or filter a listed sender.

## What is a blocklist?

A blocklist names domains and IP addresses that an operator marks as spam sources. Most operators publish theirs as a DNS zone. A receiving mail server sends one DNS query for the sender. The answer says whether the sender is on the list.

The common name is DNSBL (DNS-based blocklist). The older name is RBL (Realtime Blackhole List). This article uses "blocklist" for both.

## Why blocklists matter

Blocklists are a reputation signal. An operator adds a domain or address after reports of spam or abuse. Many receiving servers reject a listed sender during the SMTP session, before they read the message body.

Legitimate mail can end up blocked. A compromised account or a shared IP address is enough to cause a listing. What the message says does not matter.

## Domain blocklists and address blocklists

The two types answer different questions.

| Type              | What it lists                    | Example query                  |
| ----------------- | -------------------------------- | ------------------------------ |
| Domain blocklist  | Domain names that appear in spam | `example.com.dbl.spamhaus.org` |
| Address blocklist | IP addresses that sent spam      | `1.2.0.192.zen.spamhaus.org`   |

Domain blocklists mark a domain that appears in spam. Address blocklists mark the server that sent the spam. A domain can be listed while its addresses are clean. An address can be listed while the domain is clean.

## How a DNS blocklist query works

1. The receiving server takes the domain or the IP address of the sender.
2. For an IP address, the server reverses the octets and adds the zone name.
3. The server sends an A record query for the result.
4. If the name does not exist, the sender is not listed.
5. If the name exists, the answer is an address in `127.0.0.0/8`.

The code in the answer identifies the list or the reason.

### Return codes

Spamhaus ZEN returns these codes:

| Code                       | List | Reason            |
| -------------------------- | ---- | ----------------- |
| `127.0.0.2`                | SBL  | Spam source       |
| `127.0.0.3`                | CSS  | Spam source       |
| `127.0.0.4` to `127.0.0.7` | XBL  | Exploited machine |
| `127.0.0.9`                | DROP | Malicious network |
| `127.0.0.10`               | PBL  | Policy blocklist  |
| `127.0.0.11`               | PBL  | Policy blocklist  |

PBL lists addresses that a provider reserves for end users. Such an address must not send mail directly.

Spamhaus answers with an address in `127.255.255.0/24` when it refuses a query. It refuses queries through public resolvers. A refusal is not a listing.

## How the domain check uses blocklists

The **Blocklists** check has two parts:

| Subcheck               | Lists                 | Target                          |
| ---------------------- | --------------------- | ------------------------------- |
| Domain blocklists      | Spamhaus DBL          | The domain name                 |
| SPF address blocklists | Spamhaus ZEN, SpamCop | The addresses in the SPF record |

The check reads the addresses from the SPF record. For a network range, it sends one query for an address in the range. If the domain has no SPF record, the check skips the address part.

If every list fails to answer, the check shows that part as not checked.

## How to get off a blocklist

1. Open the lookup page of the operator that the check names.
2. Read the return code. The table above gives the meaning for Spamhaus ZEN.
3. Find the cause of the listing. A spam complaint or a shared IP address is common.
4. Fix the cause first. Most operators reject a request while the cause is active.
5. Ask the operator to delist the entry. For an address listing, the owner of the IP range usually sends the request.
6. Wait for the operator to process the request. Then run the check again.

If the listing is on the PBL, ask your hosting provider. The provider controls the address range.

## How to stay off a blocklist

1. Authenticate outgoing mail with <a href="{% url 'know_how:detail' slug='spf' %}">SPF</a>, <a href="{% url 'know_how:detail' slug='dkim' %}">DKIM</a>, and <a href="{% url 'know_how:detail' slug='dmarc' %}">DMARC</a>.
2. Send only to recipients who gave consent.
3. After a hard bounce, remove the address.
4. Publish a <a href="{% url 'know_how:detail' slug='ptr' %}">PTR record</a> that matches the sending domain.
5. After a change to the sending setup, run the domain check.

## Further reading

- [Spamhaus blocklists](https://www.spamhaus.org/blocklists/)
- [Spamhaus DBL](https://www.spamhaus.org/dbl/)
- [Spamhaus lookup](https://check.spamhaus.org/)
- [SpamCop blocklist](https://www.spamcop.net/bl.shtml)
- <a href="{% url 'know_how:detail' slug='spf' %}">SPF</a>: Sender Policy Framework
- <a href="{% url 'know_how:detail' slug='dmarc' %}">DMARC</a>: Domain-based Message Authentication, Reporting, and Conformance
- <a href="{% url 'know_how:detail' slug='ptr' %}">PTR</a>: Reverse DNS lookup for IP verification
