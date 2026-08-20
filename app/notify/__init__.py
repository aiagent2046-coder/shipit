"""Ways of reaching a person. Not ways of charging one.

Until now the only outward channel this product had lived inside a payment
provider: `app/billing/telegram_stars.py` owned the Bot API client, and
`app/alerts.py` reached the operator by importing it. That was fine while the
bot's reason to exist was selling Stars. It stopped being fine the moment the
Stars sale was retired, because deleting a payment provider would have taken
the only way we can tell anyone anything with it.

So the transport moved out. What lives here answers "how do we reach someone";
what lives in app/billing answers "how did they pay". A module here must not
import from app.billing, and must not know what a payment is.
"""
