"""Modelli dei dati (Pydantic v2): il contratto comune fra tutti gli agenti.

Ogni informazione che passa da un agente all'altro è uno di questi modelli, quindi
viene validata all'ingresso. Concetti principali:

- Authorization: chi ha autorizzato cosa, per quale perimetro e per quanto tempo.
- Evidence: traccia (minimizzata) di una richiesta HTTP realmente eseguita.
- Finding: un controllo e il suo stato nel ciclo di vita (vedi FindingStatus).
- AgentRun / TraceEvent: stato degli agenti e traccia delle decisioni.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str = "") -> str:
    return prefix + uuid.uuid4().hex[:12]


# =====================================================================
# Enumerazioni
# =====================================================================

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return ["critical", "high", "medium", "low", "info"].index(self.value)

    @property
    def label_it(self) -> str:
        return {"critical": "Critica", "high": "Alta", "medium": "Media",
                "low": "Bassa", "info": "Informativa"}[self.value]


class FindingKind(str, Enum):
    """Distingue un'esposizione informativa da una vulnerabilità effettiva."""
    VULNERABILITY = "vulnerability"                 # sfruttabile direttamente
    MISCONFIGURATION = "misconfiguration"           # difesa assente o debole
    INFORMATION_EXPOSURE = "information_exposure"   # informazione utile a un attaccante
    INFORMATIONAL = "informational"                 # solo contesto (es. WAF rilevato)


class FindingStatus(str, Enum):
    # prodotti dai controlli
    CANDIDATE = "candidate"            # il controllo indica un problema, da validare
    NOT_DETECTED = "not_detected"      # il controllo non ha trovato il problema, da validare
    # prodotti dalla validazione
    CONFIRMED = "confirmed"            # problema confermato da evidenze
    FALSE_POSITIVE = "false_positive"  # indicazione smentita dalle evidenze
    NOT_PRESENT = "not_present"        # assenza verificata
    # possibili in entrambe le fasi
    INCONCLUSIVE = "inconclusive"      # le evidenze non permettono di concludere
    NOT_APPLICABLE = "not_applicable"  # il controllo non ha senso su questo target
    ERROR = "error"                    # il controllo non è stato eseguito correttamente
    INFO = "info"                      # osservazione di contesto


# Transizioni ammesse (applicate dal codice in ScanContext.transition).
# Non esiste nessun percorso verso CONFIRMED che non passi da evidenze registrate.
ALLOWED_TRANSITIONS: dict[FindingStatus, set[FindingStatus]] = {
    FindingStatus.CANDIDATE: {FindingStatus.CONFIRMED, FindingStatus.FALSE_POSITIVE,
                              FindingStatus.INCONCLUSIVE},
    FindingStatus.NOT_DETECTED: {FindingStatus.NOT_PRESENT, FindingStatus.INCONCLUSIVE},
    FindingStatus.INCONCLUSIVE: {FindingStatus.CONFIRMED, FindingStatus.NOT_PRESENT},
    FindingStatus.ERROR: {FindingStatus.INCONCLUSIVE},
    FindingStatus.CONFIRMED: set(),
    FindingStatus.FALSE_POSITIVE: set(),
    FindingStatus.NOT_PRESENT: set(),
    FindingStatus.NOT_APPLICABLE: set(),
    FindingStatus.INFO: set(),
}

FINAL_STATUSES = {FindingStatus.CONFIRMED, FindingStatus.FALSE_POSITIVE, FindingStatus.NOT_PRESENT,
                  FindingStatus.INCONCLUSIVE, FindingStatus.NOT_APPLICABLE, FindingStatus.ERROR,
                  FindingStatus.INFO}


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AgentState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


# =====================================================================
# Autorizzazione e perimetro
# =====================================================================

class Origin(BaseModel):
    """Schema + host + porta: l'unità minima del perimetro."""
    model_config = ConfigDict(frozen=True)
    scheme: Literal["http", "https"]
    host: str
    port: int = Field(ge=1, le=65535)

    @field_validator("host")
    @classmethod
    def _host_lower(cls, v: str) -> str:
        v = v.strip().lower().rstrip(".")
        if not v or any(c in v for c in "/@?# \\"):
            raise ValueError("host non valido")
        return v

    @property
    def url(self) -> str:
        default = 443 if self.scheme == "https" else 80
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}" + ("" if self.port == default else f":{self.port}")

    @classmethod
    def from_url(cls, url: str) -> "Origin":
        p = urlsplit(url.strip())
        if p.scheme not in ("http", "https"):
            raise ValueError("sono ammessi solo http e https")
        if p.username or p.password:
            raise ValueError("l'URL non deve contenere credenziali")
        if not p.hostname:
            raise ValueError("host mancante")
        try:
            port = p.port or (443 if p.scheme == "https" else 80)
        except ValueError as e:
            raise ValueError("porta non valida") from e
        return cls(scheme=p.scheme, host=p.hostname, port=port)


class AuthorizationKind(str, Enum):
    ENGAGEMENT = "engagement"   # sito reale con autorizzazione scritta del proprietario
    LAB = "lab"                 # laboratorio locale (127.0.0.1)


class Authorization(BaseModel):
    """Autorizzazione legata a un target e a un perimetro precisi.

    Una scansione può partire solo con un'autorizzazione valida nel momento in cui
    parte; ogni richiesta HTTP viene confrontata con `scope`.
    """
    id: str = Field(default_factory=lambda: new_id("auth-"))
    kind: AuthorizationKind = AuthorizationKind.ENGAGEMENT
    target_url: str
    scope: list[Origin]
    authorizer_name: str = Field(min_length=2, max_length=120)
    authorizer_role: str = Field(min_length=2, max_length=120)
    operator: str = Field(min_length=2, max_length=120)
    document_ref: str = Field(default="", max_length=300)
    document_sha256: str = Field(default="", pattern=r"^([0-9a-f]{64})?$")
    valid_from: datetime
    valid_until: datetime
    allow_private_addresses: bool = False   # solo kind=lab
    allow_active_checks: bool = False       # scansione attiva ZAP: solo kind=lab
    notes: str = Field(default="", max_length=1000)
    created_at: datetime = Field(default_factory=now_utc)
    revoked: bool = False

    def is_valid_at(self, when: datetime | None = None) -> tuple[bool, str]:
        when = when or now_utc()
        if self.revoked:
            return False, "autorizzazione revocata"
        if when < self.valid_from:
            return False, "autorizzazione non ancora valida"
        if when > self.valid_until:
            return False, "autorizzazione scaduta"
        return True, "valida"

    def covers(self, origin: Origin) -> bool:
        return origin in self.scope


# =====================================================================
# Evidenze e risultati
# =====================================================================

class Evidence(BaseModel):
    """Traccia di una richiesta HTTP eseguita. Il corpo NON viene conservato:
    solo hash, lunghezza e un estratto scelto dall'agente (minimizzazione)."""
    id: str = Field(default_factory=lambda: new_id("ev-"))
    probe_id: str
    method: str
    url: str
    status_code: int = 0
    headers: dict[str, str] = Field(default_factory=dict)
    body_sha256: str = ""
    body_length: int = 0
    excerpt: str = ""
    final_url: str = ""
    redirect_chain: list[str] = Field(default_factory=list)
    redirect_blocked: str = ""          # redirect fuori perimetro non seguito
    elapsed_s: float = 0.0
    error: str | None = None
    via_proxy: str = ""                 # es. "Burp 127.0.0.1:8080 (TLS non verificato)"
    from_cache: bool = False
    recheck: bool = False               # richiesta ripetuta dall'Evidence Agent
    timestamp: datetime = Field(default_factory=now_utc)


class StatusChange(BaseModel):
    from_status: FindingStatus | None
    to_status: FindingStatus
    agent: str
    reason: str
    evidence_ids: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=now_utc)


class AINote(BaseModel):
    """Contributo dell'IA: sempre separato dai dati deterministici e marcato."""
    agent: str
    model: str
    purpose: str                       # "explanation" | "priority" | "remediation_context" | ...
    text: str = Field(max_length=1200)
    suggested_priority: Literal["alta", "media", "bassa"] | None = None
    prompt_version: str = ""
    attempts: int = 1


class RemediationAdvice(BaseModel):
    template_id: str
    title: str
    summary: str
    wordpress: str = ""
    apache: str = ""
    nginx: str = ""
    risks: str = ""
    verification: str = ""
    references: list[str] = Field(default_factory=list)
    ai_context: str = ""               # spiegazione IA (facoltativa, marcata nel report)


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: new_id("f-"))
    check_id: str                      # es. "wp.users_rest" (chiave nel catalogo)
    legacy_id: str = ""                # id della v3 corrispondente (per regressione e confronto)
    title: str
    category: Literal["recon", "wordpress", "http", "tls", "zap"]
    kind: FindingKind
    status: FindingStatus
    confidence: Confidence = Confidence.MEDIUM
    path: str = "/"
    summary: str = ""                  # evidenza leggibile (già minimizzata)
    details: dict[str, Any] = Field(default_factory=dict)
    evidence_ids: list[str] = Field(default_factory=list)
    agent: str = ""
    # valutazione del rischio (solo per CONFIRMED)
    severity: Severity | None = None
    priority: Literal["P1", "P2", "P3", "P4"] | None = None
    impact: str = ""
    likelihood: str = ""               # solo se supportata da evidenze
    rationale: str = ""
    cwe: str = ""                      # es. "CWE-200": solo dal catalogo
    cvss_vector: str = ""              # vuoto se non giustificabile
    remediation: RemediationAdvice | None = None
    ai_notes: list[AINote] = Field(default_factory=list)
    history: list[StatusChange] = Field(default_factory=list)


class AgentRun(BaseModel):
    name: str
    display_name: str
    uses_ai: bool = False
    state: AgentState = AgentState.PENDING
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_s: float = 0.0
    message: str = ""
    error: str | None = None
    requests: int = 0
    findings: int = 0


class TraceEvent(BaseModel):
    timestamp: datetime = Field(default_factory=now_utc)
    actor: str                         # "orchestrator", nome agente, "planner"
    event: str                         # "agent_start", "decision", "transition", ...
    detail: str = ""
    data: dict[str, Any] = Field(default_factory=dict)


class ScanOptions(BaseModel):
    model: str = ""
    use_ai: bool = True
    planner: Literal["deterministic", "llm"] = "deterministic"
    label: str = Field(default="", max_length=60, pattern=r"^[\w .:-]*$")
    burp: str = ""                     # "host:porta" se si vuole passare da Burp (esplicito)
    force_wordpress: bool = False      # esegue i controlli WP anche se la Recon non rileva WP
    use_zap: bool = False
    zap_url: str = ""
    zap_active: bool = False           # ammesso solo con autorizzazione di tipo LAB


class ScanResult(BaseModel):
    id: str = Field(default_factory=lambda: new_id("scan-"))
    platform_version: str
    catalog_version: str
    target: str
    host: str
    authorization: Authorization
    options: ScanOptions
    status: Literal["pending", "running", "completed", "failed", "cancelled"] = "pending"
    started_at: datetime = Field(default_factory=now_utc)
    finished_at: datetime | None = None
    duration_s: float = 0.0
    network_mode: str = ""
    user_agent: str = ""
    model_used: str = ""
    technologies: dict[str, Any] = Field(default_factory=dict)
    agents: list[AgentRun] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    trace: list[TraceEvent] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    executive_summary: str = ""
    executive_summary_ai: bool = False
    error: str | None = None
    source: Literal["v4", "legacy-v3"] = "v4"

    def counts(self) -> dict[str, int]:
        c: dict[str, int] = {}
        for f in self.findings:
            c[f.status.value] = c.get(f.status.value, 0) + 1
        return c

    def severity_counts(self) -> dict[str, int]:
        c = {s.value: 0 for s in Severity}
        for f in self.findings:
            if f.status == FindingStatus.CONFIRMED and f.severity:
                c[f.severity.value] += 1
        return c
