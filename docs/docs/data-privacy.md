---
name: Data privacy
description: Where relay runs, what it stores, for how long, and what it never does with your data
author: Johannes Maron
modified_at: 2026-11-18
---

# Data privacy

relay processes message data to deliver email and to show you reports. relay
keeps the data in Germany, keeps it for a short time, and does not build
profiles from it.

This page explains what relay stores. It also explains what relay never does
with your data.

## Hosting

relay runs on Hetzner in Falkenstein, Germany. relay makes no third-country
data transfers.

Location lookups for IP addresses run in your browser, not on relay servers.
See [Data flows](#data-flows).

## What relay stores

| Data                                                            | Where                              | How long                                              |
| --------------------------------------------------------------- | ---------------------------------- | ----------------------------------------------------- |
| Raw message bodies                                              | Object storage in Germany          | Until delivery succeeds. Then relay deletes the body. |
| Message metadata                                                | Database in Germany                | 30 days                                               |
| Message headers, SMTP transcripts, and webhook delivery records | Database in Germany                | 30 days, with the message                             |
| DMARC, TLS, and FBL reports                                     | Database in Germany                | 30 days, with the message                             |
| Suppression list                                                | Database, as salted SHA-256 hashes | Until you remove the entry                            |
| Account and organization data                                   | Database in Germany                | While your account exists                             |

relay also keeps a salted hash of an address that bounced for another
organization for 30 days. This shared block protects all senders from a dead
mailbox. The hash does not reveal the address.

The <a href="{% url 'legal:privacy' %}">privacy policy</a> is the binding
legal text. This table describes what the product does.

## What relay does not store

- **Plaintext suppression addresses.** relay stores a salted SHA-256 hash. It
  can compare an address with the list but cannot read the address back.
- **Message bodies in webhook payloads.** A webhook delivery carries a signed
  URL to the raw message. The body does not travel in the payload.
- **Passwords.** GitHub OAuth handles sign-in. relay stores no password.
- **Plaintext API keys.** relay stores a key prefix and a one-way hash. The
  plaintext key appears once at creation.
- **Feedback-ID headers that you supply.** relay replaces the header with its
  own value at submission.

## What relay does not do

- No profiling of your senders or recipients.
- No data mining.
- No model training on your message content.
- No sale or resale of message data.

relay processes message data only for delivery, bounces, provider reports, and
the dashboard.

## Data flows

| Service                | Data                                               | Purpose                                            |
| ---------------------- | -------------------------------------------------- | -------------------------------------------------- |
| GitHub OAuth           | Your GitHub identity and email address             | Sign-in and account creation                       |
| Receiving mail servers | Message content and SMTP metadata                  | Email delivery                                     |
| Public DNS resolvers   | Domain names                                       | MX, SPF, DKIM, DMARC, MTA-STS, and TLS-RPT lookups |
| ipwho.is               | IP addresses from a transmission or a DMARC report | Approximate location in the dashboard              |
| OpenFreeMap            | Map tile requests                                  | Map display in the dashboard                       |
| flagcdn.com            | Country codes from the domain check                | Country flag images                                |
| favicon.vemetric.com   | Domain names from the domain check                 | Domain icons                                       |
| Mailbox providers      | DMARC, TLS, and FBL reports                        | Sender reputation                                  |

The location, map, flag, and icon requests run in your browser. relay does
not proxy them and does not store the result. relay sends no message content
to ipwho.is or OpenFreeMap.

relay requests only the email scope from GitHub. It does not read your
repositories.

## Your rights

relay operates under the GDPR. The design supports these rights through
EU-only processing, short storage, data minimization, and encryption of
secrets at rest.

For the binding commitments, read the
<a href="{% url 'legal:terms' %}">terms of service</a> and the
<a href="{% url 'legal:privacy' %}">privacy policy</a>. The privacy policy
also explains your rights as a data subject.

## Related pages

- <a href="{% url 'docs:detail' slug='security' %}">Security</a>. Account
  access, credentials, and transport encryption.
- <a href="{% url 'docs:detail' slug='deliverability' %}">Deliverability</a>.
  The suppression list.
