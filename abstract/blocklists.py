import dataclasses
import ipaddress

REFUSAL_NETWORK = ipaddress.ip_network("127.255.255.0/24")


def reverse_pointer(address: str) -> str:
    return (
        ipaddress.ip_address(address)
        .reverse_pointer.removesuffix(".in-addr.arpa")
        .removesuffix(".ip6.arpa")
    )


@dataclasses.dataclass(frozen=True)
class BlocklistProvider:
    name: str
    zone: str
    reasons: frozendict[str, str] = dataclasses.field(default_factory=frozendict)
    keyed_zone: str = ""


PUBLIC_ADDRESS_PROVIDERS = (
    BlocklistProvider(
        "Spamhaus ZEN",
        "zen.spamhaus.org",
        frozendict(
            {
                "127.0.0.2": "SBL, spam source",
                "127.0.0.3": "CSS, spam source",
                "127.0.0.4": "XBL, exploited machine",
                "127.0.0.5": "XBL, exploited machine",
                "127.0.0.6": "XBL, exploited machine",
                "127.0.0.7": "XBL, exploited machine",
                "127.0.0.9": "DROP, malicious network",
                "127.0.0.10": "PBL, policy blocklist",
                "127.0.0.11": "PBL, policy blocklist",
            }
        ),
        keyed_zone="{key}.zen.dq.spamhaus.net",
    ),
    BlocklistProvider("SpamCop", "bl.spamcop.net"),
)

DEFAULT_ADDRESS_PROVIDERS = (
    *PUBLIC_ADDRESS_PROVIDERS,
    BlocklistProvider("Barracuda", "b.barracudacentral.org"),
    BlocklistProvider("Mailspike", "z.mailspike.net"),
    BlocklistProvider("Hostkarma", "black.junkemailfilter.com"),
    BlocklistProvider("PSBL", "psbl.surriel.com"),
    BlocklistProvider("UCEPROTECT Level 1", "dnsbl-1.uceprotect.net"),
    BlocklistProvider("SpamRATS", "all.spamrats.com"),
    BlocklistProvider("Spam Eating Monkey", "bl.spameatingmonkey.net"),
    BlocklistProvider("JustSpam", "dnsbl.justspam.org"),
    BlocklistProvider("GBUdb Truncate", "truncate.gbudb.net"),
    BlocklistProvider("0spam", "bl.0spam.org"),
    BlocklistProvider("Backscatterer", "ips.backscatterer.org"),
    BlocklistProvider("Blocklist.de", "bl.blocklist.de"),
    BlocklistProvider("SpamSources", "spamsources.fabel.dk"),
    BlocklistProvider("RV-Soft", "dnsbl.rv-soft.info"),
    BlocklistProvider("InterServer", "rbl.interserver.net"),
    BlocklistProvider("DroneBL", "dnsbl.dronebl.org"),
)
