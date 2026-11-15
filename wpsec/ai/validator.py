"""Validazione delle risposte dei modelli locali.

Ogni risposta deve essere un JSON con lo schema atteso (Pydantic). I campi testuali
vengono ripuliti e limitati in lunghezza; i campi a scelta accettano solo valori
dell'elenco. Una risposta non valida viene scartata (e ritentata dal chiamante),
MAI corretta "a fantasia".
"""

from __future__ import annotations

import json
import re
from typing import Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

T = TypeVar("T", bound=BaseModel)


class AIValidationError(ValueError):
    pass


def _clean(text: str) -> str:
    text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", str(text))
    return re.sub(r"\s+", " ", text).strip()


class _Out(BaseModel):
    model_config = ConfigDict(extra="ignore")


class ExplanationOut(_Out):
    spiegazione: str = Field(min_length=10, max_length=600)
    priorita: Literal["alta", "media", "bassa"]

    @field_validator("spiegazione", mode="before")
    @classmethod
    def _c(cls, v):
        return _clean(v)

    @field_validator("priorita", mode="before")
    @classmethod
    def _p(cls, v):
        return str(v).strip().lower()


class RemediationContextOut(_Out):
    contesto: str = Field(min_length=10, max_length=700)

    @field_validator("contesto", mode="before")
    @classmethod
    def _c(cls, v):
        return _clean(v)


class SummaryOut(_Out):
    sintesi: str = Field(min_length=20, max_length=1500)

    @field_validator("sintesi", mode="before")
    @classmethod
    def _c(cls, v):
        return _clean(v)


class PlannerOut(_Out):
    azione: str = Field(min_length=1, max_length=80)
    motivo: str = Field(default="", max_length=300)

    @field_validator("azione", mode="before")
    @classmethod
    def _a(cls, v):
        return str(v).strip().strip("\"'").lower()

    @field_validator("motivo", mode="before")
    @classmethod
    def _m(cls, v):
        return _clean(v or "")[:300]


def extract_json(text: str) -> dict:
    """Primo oggetto JSON completo (i modelli a volte aggiungono testo o <think>)."""
    if "</think>" in text:
        text = text.split("</think>")[-1]
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise AIValidationError("nessun oggetto JSON completo nella risposta")
    try:
        data = json.loads(text[start:end + 1])
    except json.JSONDecodeError as e:
        raise AIValidationError(f"JSON non valido: {e.msg}") from e
    if not isinstance(data, dict):
        raise AIValidationError("la risposta non è un oggetto JSON")
    return data


def validate_response(text: str, schema: type[T]) -> T:
    data = extract_json(text)
    try:
        return schema.model_validate(data)
    except ValidationError as e:
        campi = ", ".join(".".join(map(str, err["loc"])) for err in e.errors()[:3])
        raise AIValidationError(f"schema non rispettato ({campi})") from e
