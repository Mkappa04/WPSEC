"""Costruttori comuni per i test (autorizzazioni, client, contesti)."""

from datetime import timedelta

from wpsec import __version__
from wpsec.config.settings import Settings
from wpsec.core.context import ScanContext
from wpsec.core.models import (Authorization, AuthorizationKind, Origin, ScanOptions, ScanResult,
                               now_utc)
from wpsec.knowledge.catalog import CATALOG_VERSION
from wpsec.scanner.http_client import ScopedHttpClient

FAST = Settings(min_interval=0, request_timeout=5, max_requests=100)


def lab_auth(*urls, **kw) -> Authorization:
    scope = [Origin.from_url(u) for u in urls]
    base = dict(kind=AuthorizationKind.LAB, target_url=urls[0], scope=scope,
                authorizer_name="Laboratorio", authorizer_role="Tutor", operator="Studente",
                valid_from=now_utc() - timedelta(hours=1), valid_until=now_utc() + timedelta(days=1),
                allow_private_addresses=True)
    base.update(kw)
    return Authorization(**base)


def make_client(url, settings=FAST, auth=None, **kw) -> ScopedHttpClient:
    auth = auth or lab_auth(url)
    return ScopedHttpClient(auth, Origin.from_url(url), settings, **kw)


def make_ctx(url, settings=FAST, auth=None, **kw) -> ScanContext:
    auth = auth or lab_auth(url)
    client = make_client(url, settings, auth, **kw)
    res = ScanResult(platform_version=__version__, catalog_version=CATALOG_VERSION, target=url,
                     host=Origin.from_url(url).host, authorization=auth, options=ScanOptions())
    return ScanContext(res, settings, client)
