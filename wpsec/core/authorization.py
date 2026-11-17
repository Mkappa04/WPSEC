"""Creazione validata delle autorizzazioni (usata da API e CLI).

Regole aggiuntive rispetto al modello:
  - LAB: tutto il perimetro deve essere loopback (127.0.0.0/8, ::1, localhost); ammette
    indirizzi privati e, su richiesta, la scansione attiva;
  - ENGAGEMENT (sito reale): niente indirizzi privati né scansione attiva; servono il
    riferimento al documento firmato e una durata massima di MAX_ENGAGEMENT_DAYS;
  - il target deve essere nel perimetro (viene aggiunto automaticamente);
  - il perimetro non può contenere caratteri jolly: ogni origine è esplicita.
"""

from __future__ import annotations

import hashlib
import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Literal

from pydantic import BaseModel, Field

from wpsec.core.models import Authorization, AuthorizationKind, Origin, now_utc

MAX_ENGAGEMENT_DAYS = 90
MAX_LAB_DAYS = 365


class AuthorizationError(ValueError):
    pass


class AuthorizationRequest(BaseModel):
    kind: Literal["engagement", "lab"] = "engagement"
    target_url: str = Field(min_length=8, max_length=300)
    extra_scope: list[str] = Field(default_factory=list, max_length=10)
    authorizer_name: str = Field(min_length=2, max_length=120)
    authorizer_role: str = Field(min_length=2, max_length=120)
    operator: str = Field(min_length=2, max_length=120)
    document_ref: str = Field(default="", max_length=300)
    document_sha256: str = Field(default="", max_length=64)
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    days: int | None = Field(default=None, ge=1, le=MAX_LAB_DAYS)
    allow_active_checks: bool = False
    notes: str = Field(default="", max_length=1000)


def is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def create_authorization(req: AuthorizationRequest) -> Authorization:
    try:
        target = Origin.from_url(req.target_url)
        scope = [target] + [Origin.from_url(u) for u in req.extra_scope]
    except ValueError as e:
        raise AuthorizationError(f"URL non valido: {e}") from e
    if any("*" in o.host for o in scope):
        raise AuthorizationError("il perimetro non ammette caratteri jolly")
    scope = list(dict.fromkeys(scope))

    start = _aware(req.valid_from) if req.valid_from else now_utc()
    if req.valid_until:
        end = _aware(req.valid_until)
    else:
        end = start + timedelta(days=req.days or (30 if req.kind == "lab" else 7))
    if end <= start:
        raise AuthorizationError("la fine della validità deve seguire l'inizio")

    sha = req.document_sha256.strip().lower()
    if sha and (len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha)):
        raise AuthorizationError("document_sha256 deve essere un hash SHA-256 esadecimale")

    if req.kind == "lab":
        not_loop = [o.host for o in scope if not is_loopback_host(o.host)]
        if not_loop:
            raise AuthorizationError("un'autorizzazione di laboratorio ammette solo indirizzi "
                                     f"locali (loopback): {', '.join(not_loop)}")
        if end - start > timedelta(days=MAX_LAB_DAYS):
            raise AuthorizationError(f"durata massima di laboratorio: {MAX_LAB_DAYS} giorni")
    else:
        if req.allow_active_checks:
            raise AuthorizationError("la scansione attiva è ammessa solo in laboratorio")
        if not req.document_ref.strip():
            raise AuthorizationError("per un sito reale serve il riferimento al documento di "
                                     "autorizzazione firmato")
        loop = [o.host for o in scope if is_loopback_host(o.host)]
        if loop:
            raise AuthorizationError("per indirizzi locali usare un'autorizzazione di laboratorio")
        if end - start > timedelta(days=MAX_ENGAGEMENT_DAYS):
            raise AuthorizationError(f"durata massima per un sito reale: {MAX_ENGAGEMENT_DAYS} giorni")

    lab = req.kind == "lab"
    return Authorization(
        kind=AuthorizationKind.LAB if lab else AuthorizationKind.ENGAGEMENT,
        target_url=target.url, scope=scope, authorizer_name=req.authorizer_name.strip(),
        authorizer_role=req.authorizer_role.strip(), operator=req.operator.strip(),
        document_ref=req.document_ref.strip(), document_sha256=sha, valid_from=start,
        valid_until=end, allow_private_addresses=lab, allow_active_checks=lab and req.allow_active_checks,
        notes=req.notes)
