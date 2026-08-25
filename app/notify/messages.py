"""Every word a customer reads from us, in every language we write it in.

WHY ONE FILE. These texts were spread across the modules that send them: the
confirmation in app/billing/bank_transfer.py, the refund in
app/routes/operator.py. That is fine for one language and stops being fine at
two, because the failure mode of translations is DRIFT -- somebody improves
the English refund notice, the Russian one keeps the old wording, and nobody
finds out because nothing fails. Side by side in one file, a change that
touches only one language is visible in the diff.

WHY THESE TWO MESSAGES AND NO OTHERS. They are the moments where a person has
already given us money and is waiting: the transfer has been confirmed, or the
refund has been sent. Everything else the product says happens while they are
looking at a page in the language they chose to browse in. These two arrive
hours or days later, in an inbox, and a stranger who paid should not have to
translate our reassurance.

THE LANGUAGE IS THE PAYER'S, RECORDED AT PAYMENT TIME (migration 0033), not
guessed at send time. A guess made days later has nothing to go on: the browser
is gone, the session is gone, and the only thing left is a database row. So the
row carries it.

ENGLISH IS THE FALLBACK, and it is a real fallback rather than a default
nobody meant. Every payment made before 0033 has no locale, and inventing
Russian for them because the operator is Russian would write to English-speaking
customers in a language they did not ask for. Unknown means English.

TRANSLATIONS ARE NOT LITERAL, deliberately. The English refund notice says "a
real person reads it" because that sentence does work in English: it tells
somebody angry that they are not shouting into a queue. The Russian says the
same thing the way it is said in Russian. A translation that preserves the
words and loses the reassurance has translated nothing.
"""

from __future__ import annotations

EN = "en"
RU = "ru"

# Every language this module can write. A locale outside this set is treated as
# unknown -- see `normalize`. Kept as a tuple rather than derived from the
# dictionaries below so that adding a language is a deliberate act: you have to
# add it here AND write every message, and a missing message fails a test
# rather than silently falling back for one string.
SUPPORTED: tuple[str, ...] = (EN, RU)


def normalize(value: str | None) -> str:
    """The language to write in, from whatever was recorded on the payment.

    Accepts the shapes a browser produces -- `ru`, `ru-RU`, `RU` -- because the
    checkout defaults from `navigator.language` and that is what it gives.
    Anything unrecognised, empty or None becomes English: an unknown language
    is not a reason to withhold the message, and it is not a reason to guess.
    """
    if not value:
        return EN
    primary = value.strip().lower().replace("_", "-").split("-")[0]
    return primary if primary in SUPPORTED else EN


# --- a payment that has landed ----------------------------------------------

_CONFIRMED_SUBJECT = {
    EN: "Payment confirmed — your {product} is active",
    RU: "Платёж подтверждён — {product} активен",
}

_PRODUCT_NAME = {
    EN: {"fixpack": "Fix Pack", "pro_tier": "Drydock Pro"},
    RU: {"fixpack": "Fix Pack", "pro_tier": "Drydock Pro"},
}

_WHAT_HAPPENS_NEXT = {
    EN: {
        "fixpack": (
            "Your Fix Pack is now running. It opens a pull request against "
            "your repository with the fixes it can make, and you will hear "
            "again when it lands or if it cannot finish."
        ),
        "pro_tier": (
            "Your Drydock Pro access is active. Your API key is on the "
            "payment page for this order — open {site}/link and enter the "
            "reference below to collect it."
        ),
    },
    RU: {
        "fixpack": (
            "Fix Pack уже запущен. Он откроет пул-реквест в вашем "
            "репозитории с теми правками, которые может сделать, и мы "
            "напишем ещё раз — когда он будет готов или если не сможет "
            "завершиться."
        ),
        "pro_tier": (
            "Доступ Drydock Pro активен. Ваш API-ключ на странице оплаты "
            "этого заказа — откройте {site}/link и введите номер заказа "
            "ниже, чтобы забрать его."
        ),
    },
}

# HOW IT LANDED, not which provider took it.
#
# This was one sentence -- "We have confirmed your bank transfer" -- written
# when a bank transfer was the only way to pay. The first person to buy with a
# card was then told we had confirmed a transfer they never made, which reads
# as a message about somebody else's payment.
#
# Keyed on whether a human confirmed it rather than on the provider's name, so
# a rail added later needs no new sentence: what the payer cares about is
# whether somebody had to look, and the manual line is doing real work when
# they did -- it says the wait is over.
_CONFIRMED_OPENING = {
    EN: {
        True: "We have confirmed your bank transfer. Thank you.",
        False: "Your payment went through. Thank you.",
    },
    RU: {
        True: "Мы подтвердили ваш перевод. Спасибо.",
        False: "Ваш платёж прошёл. Спасибо.",
    },
}

_CONFIRMED_BODY = {
    EN: (
        "{opening}\n\n"
        "{next}\n\n"
        "Order reference: {reference}"
    ),
    RU: (
        "{opening}\n\n"
        "{next}\n\n"
        "Номер заказа: {reference}"
    ),
}


def confirmation_subject(*, product: str, locale: str | None) -> str:
    lang = normalize(locale)
    name = _PRODUCT_NAME[lang].get(product, _PRODUCT_NAME[lang]["pro_tier"])
    return _CONFIRMED_SUBJECT[lang].format(product=name)


def confirmation_body(
    *, product: str, reference: str, site_url: str, locale: str | None,
    confirmed_by_hand: bool,
) -> str:
    """`confirmed_by_hand` has no default, deliberately. A caller that forgets
    it is a caller that would have picked one of these two sentences by
    accident, and the wrong one is a message about a payment the reader never
    made."""
    lang = normalize(locale)
    nexts = _WHAT_HAPPENS_NEXT[lang]
    what = nexts.get(product, nexts["pro_tier"]).format(site=site_url)
    return _CONFIRMED_BODY[lang].format(
        opening=_CONFIRMED_OPENING[lang][bool(confirmed_by_hand)],
        next=what, reference=reference,
    )


# --- a refund the operator has sent -----------------------------------------

_REFUND_SUBJECT = {
    EN: "Your Drydock refund",
    RU: "Возврат средств Drydock",
}

# THE OPERATOR'S REASON IS NEVER IN HERE, in any language. It is a note for the
# books -- "customer says the Fix Pack was wrong", "duplicate charge" -- written
# to be true rather than to be read by the person it is about. Quoting it back
# is at best clumsy and at worst an accusation.
_REFUND_BODY = {
    EN: (
        "We have refunded {money}.\n\n"
        "It was sent back the same way it arrived. How long it takes to "
        "appear depends on your bank, not on us — for a card transfer that is "
        "usually a few business days.\n\n"
        "{reference}"
        "If it has not arrived within a week, tell us."
    ),
    RU: (
        "Мы вернули {money}.\n\n"
        "Деньги отправлены тем же путём, которым пришли. Сколько они будут "
        "идти, зависит от вашего банка, а не от нас — для карточного перевода "
        "обычно несколько рабочих дней.\n\n"
        "{reference}"
        "Если через неделю деньги не придут — напишите нам."
    ),
}

_REFUND_REFERENCE_LINE = {
    EN: "Order reference: {reference}\n\n",
    RU: "Номер заказа: {reference}\n\n",
}

# What stands in for the amount when the row carries none. Not "0.00": a
# refund notice that names the wrong number is worse than one that names none,
# and this text is read by somebody counting their money.
_THE_PAYMENT = {
    EN: "your payment",
    RU: "ваш платёж",
}


def refund_subject(*, locale: str | None) -> str:
    return _REFUND_SUBJECT[normalize(locale)]


# --- how to reach a person, which depends on where they are reading ---------

# The channel the "reply" instruction is true on. Anything else gets the
# address, and that default is the safe direction: a channel this module has
# never heard of is a channel where we do not know that replying works.
_REPLYABLE = "email"

SUPPORT_ADDRESS = "support@drydock.co"

# THIS SENTENCE IS THE WHOLE POINT OF THE MESSAGE and it was wrong.
#
# Both notifications close by telling somebody anxious about money how to
# reach a human. Until 2026-08-21 that sentence lived inside the body, one
# text for every channel, and the Russian said "ответьте на это письмо" --
# reply to this EMAIL. It went out over Telegram unchanged.
#
# What happened next is the part that matters. The bot answers unknown text
# with {"ok": true, "handled": "ignored"} and forwards nothing, so a customer
# who did as instructed reached nobody, believed they had contacted support,
# and waited. That is precisely the road to a chargeback that the refund
# notice exists to close.
#
# The English survived by luck: "reply to this message" is channel-neutral, so
# nothing looked broken and no test could see it. Both languages carried the
# same facts -- the amount, the reference, no operator reason -- which is all
# test_notify_messages.py knew how to compare. What had drifted was whether
# the sentence was TRUE where it was read, and that is not a property of a
# translation pair.
#
# So it is keyed on channel first and language second, and it is not part of
# the body: a body cannot know where it is going, and the router can.
_SIGN_OFF = {
    _REPLYABLE: {
        EN: "Reply to this message — a real person reads it.",
        RU: "Просто ответьте на это письмо. Его читает живой человек.",
    },
    "elsewhere": {
        EN: f"Write to {SUPPORT_ADDRESS} — a real person reads it.",
        RU: f"Напишите на {SUPPORT_ADDRESS} — там отвечает живой человек.",
    },
}


def sign_off(*, channel: str, locale: str | None) -> str:
    """How to reach a person, phrased for the channel this is being sent on.

    `channel` is one of app/notify/router.py's channel names. It is compared
    rather than imported to keep this module free of the router -- these are
    words, and the router is machinery.
    """
    key = _REPLYABLE if channel == _REPLYABLE else "elsewhere"
    return _SIGN_OFF[key][normalize(locale)]


def refund_body(
    *, amount: float | None, currency: str | None, reference: str,
    locale: str | None,
) -> str:
    lang = normalize(locale)
    quoted = f"{float(amount):.2f}" if amount is not None else ""
    money = f"{quoted} {currency or ''}".strip() or _THE_PAYMENT[lang]
    line = (_REFUND_REFERENCE_LINE[lang].format(reference=reference)
            if reference else "")
    return _REFUND_BODY[lang].format(money=money, reference=line)
