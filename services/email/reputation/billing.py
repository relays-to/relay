import decimal

from django.conf import settings


def month_cost(messages, *, is_free=False):
    """Return what `messages` cost this month, past the free tier, and nothing for a free organization."""
    billable = (
        0 if is_free else max(messages - max(settings.FREE_MONTHLY_MESSAGES, 0), 0)
    )
    price = max(
        decimal.Decimal(0), decimal.Decimal(str(settings.PRICE_PER_1000_MESSAGES))
    )
    return (price * billable / decimal.Decimal(1000)).quantize(decimal.Decimal("0.01"))


def overage_price():
    """Return the price per 1,000 messages, or None when sending is free."""
    price = max(
        decimal.Decimal(0), decimal.Decimal(str(settings.PRICE_PER_1000_MESSAGES))
    )
    return price or None
