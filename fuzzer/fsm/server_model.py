from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fuzzer.fsm.storage import FSMStorage, ResourceRef
from fuzzer.graphql.client import GraphQLResponse
from fuzzer.oracle.base import has_errors

ID_KEYS = {"id", "_id", "uuid"}


def _has_real_data(body: Any) -> bool:
    """True only if the response carries a non-null data value.

    GraphQL returns ``{"data": {"field": null}, "errors": [...]}`` when a
    resolver throws, so a plain ``data`` key is not enough to call an operation
    productive — the field must actually resolve to a value.
    """
    if isinstance(body, list):
        return any(_has_real_data(item) for item in body)
    if not isinstance(body, dict):
        return False
    data = body.get("data")
    if isinstance(data, dict):
        return any(value is not None for value in data.values())
    return data is not None and data != {}


@dataclass
class ServerModel:
    """Run-scoped, persistent knowledge learned by observing the live server.

    Unlike per-chromosome ``FSMStorage`` (which is reset for every chromosome to
    keep GA fitness isolated), a single ``ServerModel`` survives the whole run so
    the fuzzer adapts its behaviour to what the server actually does — e.g. it
    learns that ``login`` never succeeds and stops trying it, or that an
    operation requires a session before it returns data.
    """

    responsive_operations: set[str] = field(default_factory=set)
    observed_auth_required: dict[str, bool] = field(default_factory=dict)
    nonproductive_ops: set[str] = field(default_factory=set)
    op_attempts: dict[str, int] = field(default_factory=dict)
    op_errors: dict[str, int] = field(default_factory=dict)
    harvested_ids: set[str] = field(default_factory=set)
    harvested_resources: list[ResourceRef] = field(default_factory=list)
    rate_limited: bool = False

    def observe(
        self,
        response: GraphQLResponse | None,
        operation_name: str | None,
        auth_mode: str,
        owner_actor: str | None = None,
    ) -> None:
        if response is None:
            return
        if response.status_code == 429:
            self.rate_limited = True
            return
        if not operation_name:
            return

        self.op_attempts[operation_name] = self.op_attempts.get(operation_name, 0) + 1
        data = _has_real_data(response.body)
        errors = has_errors(response)

        if data:
            self.responsive_operations.add(operation_name)
        if errors and not data:
            self.op_errors[operation_name] = self.op_errors.get(operation_name, 0) + 1

        # An operation that has been tried twice and only ever errors (never
        # returns data) is treated as non-productive (e.g. the broken `login`).
        attempts = self.op_attempts[operation_name]
        if (
            attempts >= 2
            and operation_name not in self.responsive_operations
            and self.op_errors.get(operation_name, 0) == attempts
        ):
            self.nonproductive_ops.add(operation_name)
        else:
            self.nonproductive_ops.discard(operation_name)

        # Learn auth requirement from cookie-less attempts: erroring without a
        # session suggests auth is required; data without one means it is public.
        if auth_mode == "no_token":
            if data:
                self.observed_auth_required[operation_name] = False
            elif errors:
                self.observed_auth_required.setdefault(operation_name, True)

        self._harvest_ids(response.body)

    def note_resource(self, resource_type: str, resource_id: str, owner_actor: str | None) -> None:
        self.harvested_ids.add(str(resource_id))
        if not any(r.id == str(resource_id) and r.owner_actor == owner_actor for r in self.harvested_resources):
            self.harvested_resources.append(ResourceRef(resource_type, str(resource_id), owner_actor))

    def is_auth_required(self, operation_name: str) -> bool | None:
        return self.observed_auth_required.get(operation_name)

    def is_nonproductive(self, operation_name: str | None) -> bool:
        return bool(operation_name) and operation_name in self.nonproductive_ops

    def seed_storage(self, storage: FSMStorage, allow_instance: bool) -> None:
        """Warm a fresh per-chromosome storage with harvested knowledge.

        ``allow_instance`` carries concrete resource ids/owners across
        chromosomes (only safe when the target is not reset between them).
        """
        if not allow_instance:
            return
        for resource_id in self.harvested_ids:
            storage.known_ids.add(resource_id)
        for resource in self.harvested_resources:
            if not storage.get_resource(owner_actor=resource.owner_actor, state="active"):
                storage.add_resource(ResourceRef(resource.resource_type, resource.id, resource.owner_actor, resource.state))

    def to_dict(self) -> dict[str, Any]:
        return {
            "responsive_operations": sorted(self.responsive_operations),
            "observed_auth_required": self.observed_auth_required,
            "nonproductive_ops": sorted(self.nonproductive_ops),
            "harvested_ids": sorted(self.harvested_ids),
            "harvested_resources": [
                {"resource_type": r.resource_type, "id": r.id, "owner_actor": r.owner_actor, "state": r.state}
                for r in self.harvested_resources
            ],
            "rate_limited": self.rate_limited,
        }

    def _harvest_ids(self, value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key.lower() in ID_KEYS and child is not None and not isinstance(child, (dict, list)):
                    self.harvested_ids.add(str(child))
                self._harvest_ids(child)
        elif isinstance(value, list):
            for item in value:
                self._harvest_ids(item)
