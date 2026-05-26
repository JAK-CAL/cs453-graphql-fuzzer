from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Actor:
    name: str
    username: str | None = None
    password: str | None = None
    token: str | None = None
    role: str = "user"


@dataclass
class ResourceRef:
    resource_type: str
    id: str
    owner_actor: str | None = None
    state: str = "active"
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class FSMStorage:
    actors: dict[str, Actor] = field(default_factory=dict)
    active_actor: str | None = None
    resources: dict[str, list[ResourceRef]] = field(default_factory=dict)
    previous_responses: list[dict[str, Any]] = field(default_factory=list)
    known_ids: set[str] = field(default_factory=set)
    valid_tokens: list[str] = field(default_factory=list)
    invalid_tokens: list[str] = field(default_factory=list)

    def add_token(self, actor_name: str, token: str) -> None:
        actor = self.actors.setdefault(actor_name, Actor(name=actor_name))
        actor.token = token
        self.active_actor = actor_name
        if token not in self.valid_tokens:
            self.valid_tokens.append(token)

    def get_token(self, actor_name: str | None = None) -> str | None:
        if actor_name and actor_name in self.actors:
            return self.actors[actor_name].token
        if self.active_actor and self.active_actor in self.actors:
            return self.actors[self.active_actor].token
        return self.valid_tokens[0] if self.valid_tokens else None

    def add_resource(self, resource: ResourceRef) -> None:
        self.resources.setdefault(resource.resource_type, []).append(resource)
        self.known_ids.add(str(resource.id))

    def get_resource(self, resource_type: str | None = None, owner_actor: str | None = None, state: str | None = "active") -> ResourceRef | None:
        buckets = [self.resources.get(resource_type, [])] if resource_type else self.resources.values()
        for bucket in buckets:
            for resource in bucket:
                if owner_actor is not None and resource.owner_actor != owner_actor:
                    continue
                if state is not None and resource.state != state:
                    continue
                return resource
        return None

    def extract_ids_from_response(self, response_body: Any) -> None:
        def walk(value: Any) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    if key.lower() in {"id", "_id", "uuid"} and child is not None:
                        self.known_ids.add(str(child))
                    if key.lower() in {"token", "access_token", "jwt"} and isinstance(child, str):
                        self.add_token(self.active_actor or "default", child)
                    walk(child)
            elif isinstance(value, list):
                for item in value:
                    walk(item)

        if isinstance(response_body, dict):
            self.previous_responses.append(response_body)
        walk(response_body)
