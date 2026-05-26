from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


SENSITIVE_KEYWORDS = [
    "admin",
    "user",
    "private",
    "secret",
    "token",
    "password",
    "permission",
    "role",
    "email",
    "profile",
    "owner",
]


@dataclass
class Argument:
    name: str
    type_name: str
    required: bool = False
    raw_type: dict[str, Any] | None = None


@dataclass
class Operation:
    name: str
    operation_type: str
    args: list[Argument] = field(default_factory=list)
    return_type: str | None = None
    selectable_fields: list[str] = field(default_factory=list)
    nested_fields: dict[str, str] = field(default_factory=dict)
    auth_required_guess: bool = False
    sensitive_field_guess: bool = False
