"""Private encrypted delivery grants, bound to the payment that funded work.

Payment receipts may share a job after duplicate payment reconciliation. Only
the immutable funding key identifies which receipt can authorize that job.
Nothing in this store returns a decrypted GitHub credential.
"""
from __future__ import annotations

import uuid

from app import db
from app.fixpack_funding import funding_key


def _owns_funding(row: dict) -> bool:
    provider, reference = row.get("provider"), row.get("external_ref")
    return (
        isinstance(provider, str) and isinstance(reference, str)
        and row.get("funding_key") == funding_key(provider, reference)
        and row.get("audit_id") is not None
        and row["audit_id"] == row.get("job_audit_id")
    )


class PaidDeliveryStore:
    async def funding_pending(self, job_id: str) -> bool:
        """Recognize the exact invoice while confirmation links it to its job.

        grant_fixpack reserves the job before completing its payment. A worker
        can claim inside that gap. This is a reason to defer, never authority
        to execute work or to borrow another pending invoice's credential.
        """
        try:
            parsed_id = uuid.UUID(str(job_id))
            pool = await db.get_pool()
        except (ValueError, db.DatabaseNotConfigured):
            return False
        async with pool.connection() as conn:
            cur = await conn.execute(
                """select p.provider, p.external_ref, p.audit_id,
                          j.audit_id as job_audit_id, j.funding_key
                     from fixpack_jobs j join payments p on p.audit_id = j.audit_id
                    where j.id = %s and j.funding_key is not null
                      and p.status = 'pending' and p.product = 'fixpack'
                      and (p.fixpack_job_id is null or p.fixpack_job_id = j.id)""",
                (parsed_id,),
            )
            rows = await cur.fetchall()
        return any(_owns_funding(row) for row in rows)

    async def await_authorization(self, job_id: str, reason: str) -> None:
        """Park only the running lease, without spending a generation attempt."""
        try:
            parsed_id = uuid.UUID(str(job_id))
            pool = await db.get_pool()
        except (ValueError, db.DatabaseNotConfigured):
            return
        async with pool.connection() as conn:
            await conn.execute(
                """update fixpack_jobs set status = 'awaiting_authorization',
                          started_at = null, attempts = greatest(attempts - 1, 0),
                          detail = %s
                    where id = %s and status = 'running'""",
                (reason, parsed_id),
            )

    async def get_for_job(self, job_id: str) -> dict | None:
        try:
            parsed_id = uuid.UUID(str(job_id))
            pool = await db.get_pool()
        except (ValueError, db.DatabaseNotConfigured):
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """select p.id as payment_id, p.provider, p.external_ref,
                          p.audit_id, j.audit_id as job_audit_id, j.funding_key,
                          g.encrypted_grant
                     from fixpack_jobs j
                     join payments p on p.fixpack_job_id = j.id
                     left join fixpack_delivery_grants g on g.payment_id = p.id
                    where j.id = %s and p.status = 'completed'
                      and p.product = 'fixpack'""", (parsed_id,),
            )
            rows = await cur.fetchall()
        for row in rows:
            if _owns_funding(row):
                return {
                    "payment_id": str(row["payment_id"]),
                    "provider": row["provider"],
                    "external_ref": row["external_ref"],
                    "audit_id": str(row["audit_id"]),
                    "encrypted_grant": row["encrypted_grant"],
                }
        return None

    async def replace_for_payment(self, payment_id: str, encrypted_grant: str) -> bool:
        """Renew a paused paid job once; never resurrect terminal/running work.

The route must first authenticate the receipt and audit and verify the new
credential against GitHub. Row locks serialize renewal with refunds and other
renewals; the secret write and requeue commit in the same transaction.
"""
        try:
            parsed_id = uuid.UUID(str(payment_id))
            pool = await db.get_pool()
        except (ValueError, db.DatabaseNotConfigured):
            return False
        async with pool.connection() as conn:
            cur = await conn.execute(
                """select p.id as payment_id, p.provider, p.external_ref,
                          p.audit_id, j.audit_id as job_audit_id, j.funding_key,
                          j.id as job_id
                     from payments p join fixpack_jobs j on p.fixpack_job_id = j.id
                    where p.id = %s and p.status = 'completed'
                      and p.product = 'fixpack'
                      and j.status = 'awaiting_authorization'
                    for update of p, j""", (parsed_id,),
            )
            row = await cur.fetchone()
            if row is None or not _owns_funding(row):
                return False
            await conn.execute(
                """insert into fixpack_delivery_grants (payment_id, encrypted_grant)
                   values (%s, %s) on conflict (payment_id) do update
                   set encrypted_grant = excluded.encrypted_grant, updated_at = now()""",
                (parsed_id, encrypted_grant),
            )
            await conn.execute(
                """update fixpack_jobs set status = 'paid', started_at = null,
                          detail = null
                    where id = %s and status = 'awaiting_authorization'""",
                (row["job_id"],),
            )
        return True

    async def clear_for_job(self, job_id: str) -> None:
        """Erase all retained credentials for a delivered job, including duplicates."""
        try:
            parsed_id = uuid.UUID(str(job_id))
            pool = await db.get_pool()
        except (ValueError, db.DatabaseNotConfigured):
            return
        async with pool.connection() as conn:
            await conn.execute(
                """delete from fixpack_delivery_grants g using payments p
                    where g.payment_id = p.id and p.fixpack_job_id = %s""",
                (parsed_id,),
            )
