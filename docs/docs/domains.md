---
name: Managed domains and DNS
description: Use the managed sender domain, add your own domain, and verify the DNS records
author: Johannes Maron
---

# Managed domains and DNS

relay runs its own authoritative nameserver. You publish one delegation for
the sender subdomain and a small record set at your root domain. relay
serves the DNS values under the sender subdomain, so a key or policy change
needs no edit at your root domain.

## Domain types

| Type | Example | Who creates it | What it does |
| --- | --- | --- | --- |
| Managed sender domain | `acme.open.relays.to` | relay, at signup | Sends mail immediately with no DNS setup. |
| Custom domain | `acme.com` | You | Sends and receives mail with your own name. |
| Receiving domain | `app.acme.com` | You | Receives mail on a subdomain. |

Every organization gets a managed sender domain. It is pre-verified and
cannot be deleted.

## Send from the managed domain

Open **Credentials**. Then create an SMTP credential. Use the managed domain
in your From-address, for example `billing@acme.open.relays.to`.

The relay nameserver serves every record for the managed domain. You do not
edit DNS.

## Add your own domain

### 1. Add the domain

Open **Domains**. Then click **Add domain**. Enter the root domain, for
example `acme.com`.

relay creates the DKIM keys for the domain and shows the records to publish.

To send from a subdomain, add the subdomain as a domain. Then verify its
records. A From-address must match a domain in your organization.

### 2. Delegate the sender subdomain

Publish NS records for the sender subdomain, for example
`mail.relay.acme.com`. Use the nameservers from the domain page:

| Type | Name | Value |
| --- | --- | --- |
| `NS` | `mail.relay.acme.com` | `ns1.relays.to` |
| `NS` | `mail.relay.acme.com` | `ns2.relays.to` |

Sending and reporting are not available until the delegation is live. The
relay nameserver must serve the sender subdomain.

### 3. Publish the sending records

Open the **Sending** tab. Then publish the records that it shows.

| Type | Name | Value |
| --- | --- | --- |
| `TXT` | `acme.com` | `v=spf1 include:mail.relay.acme.com -all` |
| `CNAME` | `relay-rsa2048._domainkey.acme.com` | `relay-rsa2048._domainkey.mail.relay.acme.com` |
| `CNAME` | `relay-ed25519._domainkey.acme.com` | `relay-ed25519._domainkey.mail.relay.acme.com` |

The root SPF record includes the sender subdomain. The DKIM CNAMEs point at
the public keys in the relay zone. relay can send with the RSA key alone.
relay needs both CNAMEs for the full sending check.

### 4. Publish the reporting records

Open the **Reporting** tab. Then publish the records that it shows.

| Type | Name | Value |
| --- | --- | --- |
| `TXT` | `_dmarc.acme.com` | `v=DMARC1; p=reject; sp=reject; adkim=r; aspf=r; rua=mailto:dmarc@mail.relay.acme.com; ruf=mailto:ruf@mail.relay.acme.com;` |
| `CNAME` | `_mta-sts.acme.com` | `_mta-sts.mail.relay.acme.com` |
| `CNAME` | `mta-sts.acme.com` | `mta-sts.mail.relay.acme.com` |
| `CNAME` | `_smtp._tls.acme.com` | `_smtp._tls.mail.relay.acme.com` |

The DMARC record tells receivers to reject failing mail. It also tells them
to send reports to relay. The MTA-STS and TLS-RPT CNAMEs delegate their
values to the sender subdomain, so relay serves them.

The protocol background is in the know-how articles on
<a href="{% url 'know_how:detail' slug='spf' %}">SPF</a>,
<a href="{% url 'know_how:detail' slug='dkim' %}">DKIM</a>,
<a href="{% url 'know_how:detail' slug='dmarc' %}">DMARC</a>,
<a href="{% url 'know_how:detail' slug='mta-sts' %}">MTA-STS</a>, and
<a href="{% url 'know_how:detail' slug='tls-rpt' %}">TLS-RPT</a>.

If a name already has a TXT record, delete it. Then add the CNAME. A CNAME
cannot share a name with another record.

### 5. Publish the receiving record

To receive mail on the domain, open the **Receiving** tab. Then publish its
MX records.

| Type | Name | Priority | Value |
| --- | --- | --- | --- |
| `MX` | `acme.com` | `10` | `mx1.relays.to` |
| `MX` | `acme.com` | `10` | `mx2.relays.to` |

A sending-only domain can leave this record out.

### 6. Verify DNS

Click **Verify DNS**. relay reads the live DNS and shows the state of each
record. The tabs show the sending, receiving, and reporting readiness.

Verification runs per record. Fix a failing record. Then verify again.

Each tab has a **Zone file** download. If your DNS provider imports zone
files, use it. The file lists the records for that group with an explicit
TTL.

## MTA-STS

relay serves an MTA-STS policy in `enforce` mode for every domain that
publishes the MTA-STS records. The policy lists the MX hosts that can receive
mail for the domain. The policy has a 7-day maximum age.

If your domain receives mail through another provider, list those MX hosts on
the domain page. Then save the form. Enter one host per line. relay allows
RFC 8461 wildcard patterns such as `*.example.com`. An empty field uses the
live MX records.

Verification fails if a live MX record is not in the list. The policy id
changes when you change the list. Senders then fetch the new policy.

## Receiving-only domain

You can receive mail on a subdomain without sending from it. Add the subdomain
as a domain, for example `app.acme.com`. Publish only its MX record. Then
verify it.

The sending and reporting tabs can stay incomplete. A missing record in those
tabs does not block inbound mail.

Then create a webhook endpoint for the domain in **Inbound email**. See
<a href="{% url 'docs:detail' slug='receiving' %}">Receiving</a>.

## Domain ownership

A domain belongs to one organization. relay rejects a domain that overlaps a
domain of another organization.

You cannot add a subdomain of `open.relays.to` or of the relay platform
domain. relay manages those names.

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| The delegation check fails | The NS records are missing or wrong. | Publish the NS records from the domain page. |
| The SPF check fails | The root TXT record is missing or has a typo. | Publish the exact SPF value from the **Sending** tab. |
| A DKIM check fails | The CNAME name or target is wrong. | Copy the selector name and target from the page. |
| The DMARC check fails | The TXT record is missing or has no relay reporting address. | Publish the exact DMARC value from the **Reporting** tab. |
| The MTA-STS check fails | A CNAME is wrong, or a live MX record is not in the policy. | Publish both CNAMEs. Then add the MX host to the policy. |
| The TLS-RPT check fails | The `_smtp._tls` CNAME is missing or wrong. | Publish the CNAME from the **Reporting** tab. |
| A check stays pending after you publish a record | DNS caching. | Wait for the TTL of your zone. Then verify again. |

## Related pages

- <a href="{% url 'docs:detail' slug='sending' %}">Sending</a>. Connect your
  application and submit a message.
- <a href="{% url 'docs:detail' slug='receiving' %}">Receiving</a>. Accept
  inbound mail and create webhook endpoints.
- <a href="{% url 'docs:detail' slug='security' %}">Security</a>. TLS and
  domain ownership.
