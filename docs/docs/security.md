---
name: Security
description: Protect your account, credentials, signing keys, and message transport
author: Johannes Maron
---

# Security

relay stores your message content and controls the DNS for your sender
domains. This page explains how relay protects that access and what you must
do on your side.

## Account access

relay uses GitHub OAuth for sign-in. relay stores your GitHub identity and
your email address, but no password. GitHub proves your identity at each
sign-in.

An organization owns its domains, credentials, endpoints, and messages. One
organization cannot read the data of another organization.

Only members of an organization can open its pages. Members with the `admin`
role can manage other members. Members with the `write` role can use the
email features.

The dashboard accepts HTTPS only. The HSTS policy stops a browser from
falling back to plain HTTP.

## Domain ownership

A domain belongs to one organization. relay rejects a domain that overlaps a
domain of another organization.

You cannot add a subdomain of the relay platform domain or of the managed
sender zone. relay manages those names.

## SMTP credentials

Create one credential for each application. Give it a name, so you can tell
credentials apart in the dashboard and in support messages.

relay stores these values for a credential:

- A visible key prefix.
- A one-way hash of the key.
- The name, type, creation time, and last use.

relay does not store the plaintext key. The key appears once at creation.
Copy it then. If you lose it, delete the credential. Then create a new one.

A credential belongs to one organization. Every stored message records the
credential that submitted it. This record helps the support team trace a
send.

### Rotate a credential

1. Create a new credential.
2. Deploy the new key to your application.
3. Make sure that the application sends with the new credential.
4. Delete the old credential.

A new credential changes no message content and no DNS record.

### Sandbox credentials

A sandbox credential accepts and scans messages but never delivers them. Use
it in development and test environments. See
<a href="{% url 'docs:detail' slug='sending' %}">Sending</a>.

## Webhook signing secrets

Each inbound endpoint has its own signing secret in `whsec_` form. relay
stores the secret encrypted. The secret appears in the dashboard for you to
copy.

relay signs every delivery with the secret. Before you process a payload,
verify the signature. See
<a href="{% url 'docs:detail' slug='receiving' %}">Receiving</a> for the
verification code.

To rotate a webhook secret, create a new endpoint. Then deploy its secret.
Then delete the old endpoint.

## Encryption in transit

Email is a store-and-forward system. Every mail server on the path reads the
message. relay encrypts every hop it controls.

### Submission

Your application submits over TLS only:

- Port 465 uses TLS from the first byte.
- Port 587 needs STARTTLS before AUTH.

relay rejects plaintext submission on both ports.

### Delivery

relay delivers with STARTTLS on port 25. If the recipient domain publishes an
MTA-STS policy, relay applies the policy before delivery. In `enforce` mode,
the policy blocks hosts outside the list and needs a valid certificate.

### Inbound

Remote servers deliver to the relay MX on port 25 with STARTTLS. The MX
certificate matches the MX hostname in your DNS record. relay records the TLS
version, the cipher, and the certificate of the sender.

The dashboard shows MTA-STS and TLS-RPT records for your domains. These
records ask senders to use TLS and to report failures.

Each message records whether it traveled over TLS. Open a transmission to see
the TLS details.

### What relay cannot encrypt

relay cannot encrypt a message end to end. Every server that handles the
message can read it.

If your content needs end-to-end protection, encrypt it in your application
before submission, for example with S/MIME or PGP. relay then carries the
encrypted content.

## Signing keys at rest

Each domain has an RSA-2048 key and an Ed25519 key for DKIM. relay generates
the keys when you add the domain. relay encrypts the private keys before
storage. The database never holds a plaintext private key.

Only the public keys appear in DNS. A receiver can verify a signature but
cannot create one.

## Inbound protections

relay runs these checks before an inbound message reaches your endpoint:

- The recipient domain must belong to your organization.
- relay rejects a message that fails a sender `p=reject` DMARC policy at SMTP.
- A `p=quarantine` result stores the message as quarantined.
- The spam and malware scan quarantines a message that fails.
- A quarantined message never reaches a webhook.

The message detail page shows an HTML body in a sandboxed frame. The frame
runs no scripts and blocks forms and objects. Remote images load by default,
so the message looks as the sender wrote it.

## Protect your secrets

- Never send a credential, a webhook secret, or a private key in an email
  message.
- Store credentials in your application secret manager, not in source code.
- Use one credential per application.
- Delete a credential as soon as you suspect a leak.
- Keep the dashboard account of each member protected with GitHub two-factor
  authentication.

## Related pages

- <a href="{% url 'docs:detail' slug='sending' %}">Sending</a>. SMTP setup and
  authentication.
- <a href="{% url 'docs:detail' slug='receiving' %}">Receiving</a>. Webhook
  signatures and inbound checks.
- <a href="{% url 'docs:detail' slug='data-privacy' %}">Data privacy</a>.
  Hosting, retention, and data flows.
