---
name: Mail sovereignty
description: Which countries control the mail for a domain
author: Johannes Maron
modified_at: 2026-11-18
---

# Mail sovereignty

> **TL;DR**: The flags show the countries that control the mail sent and received by a domain.

## What the flags mean

The domain check shows one flag for each country that controls the mail sent and received by the domain. The check covers the MX hosts that receive mail and the addresses that SPF allows to send mail. A flag means a company in that country runs part of the mail path. The company can be subject to the laws of that country, including orders to disclose data.

The check uses two sources:

1. **The mail provider.** The MX hostname identifies the service that operates the mailbox. For example, `contoso-com.mail.protection.outlook.com` belongs to Microsoft 365. The flag is the country of the parent company of the provider.
2. **The network.** The MX hosts and the SPF addresses resolve to IP addresses. The check looks up each address in the [Team Cymru](https://team-cymru.com/community-services/ip-asn-mapping/) IP-to-ASN service. The flag is the registration country of the ASN that owns the address.

The check shows each country only once. A domain that uses Microsoft 365 on a Microsoft network shows one US flag, not two. The sender side can include many third-party services. The check samples the first five sender addresses.

Flag images come from [flagcdn.com](https://flagcdn.com/). The request carries the country code, not the domain you checked.

## What the flags do not mean

### The flag is not the server location

A company in the United States can control a server in Frankfurt. The existing IP address dialog shows the location reported for the address. That is a different question.

### The flag is not the country of the domain owner

Public registries do not always publish the country of the owner. Most gTLD registries hide registrant data. DENIC does not publish domain holder data for `.de`. The check does not guess. It only shows the infrastructure it can see.

### The flag is not a legal opinion

A company can have subsidiaries, data processing agreements, and data boundaries. These change the practical reach of a jurisdiction. The flags are not legal advice.

### The flag does not cover every party

A reseller or an email gateway can hide the backend. The check only sees the MX records and the SPF addresses that the domain publishes. If a gateway forwards to another provider, only the gateway and its network appear.

## Provider jurisdictions

The provider map is in `jurisdictions.yaml`. It uses the country of the parent company, not the location of a data center. Some examples:

| Provider         | Country       |
| ---------------- | ------------- |
| Microsoft 365    | United States |
| Google Workspace | United States |
| Amazon           | United States |
| mailbox.org      | Germany       |
| Hetzner          | Germany       |
| IONOS            | Germany       |
| OVHcloud         | France        |
| Proton           | Switzerland   |
| Infomaniak       | Switzerland   |
| Fastmail         | Australia     |
| Zoho             | India         |

The map does not include every provider. If the map does not include a provider, the check uses the ASN country of its MX network.

## Why this is not part of the tier

The tier grades email authentication and deliverability. It measures things the domain owner can fix, such as <a href="{% url 'know_how:detail' slug='spf' %}">SPF</a>, <a href="{% url 'know_how:detail' slug='dmarc' %}">DMARC</a>, and <a href="{% url 'know_how:detail' slug='mta-sts' %}">MTA-STS</a>.

Sovereignty is a policy preference. A US company can choose US infrastructure. A German company can choose German infrastructure. The check shows the facts and leaves the judgment to the reader.
