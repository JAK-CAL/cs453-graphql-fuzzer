from __future__ import annotations

from typing import Any

from fuzzer.graphql.client import GraphQLClient


INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      kind
      name
      fields(includeDeprecated: true) {
        name
        args { name type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } }
        type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
      }
    }
  }
}
"""


COMMON_PROBES = ["users", "user", "posts", "post", "login", "me", "profile"]


def introspect_schema(client: GraphQLClient) -> dict[str, Any] | None:
    response = client.execute(INTROSPECTION_QUERY, {}, "no_token")
    if response.timeout or response.status_code == 0:
        return {"probe_only": True, "error": response.text[:300], "findings": []}
    if isinstance(response.body, dict) and response.body.get("data", {}).get("__schema"):
        return response.body["data"]["__schema"]
    return None


def probe_schema_placeholder(client: GraphQLClient) -> dict[str, Any]:
    findings = []
    for name in COMMON_PROBES:
        query = f"query {{ {name} }}"
        resp = client.execute(query, {}, "no_token")
        if resp.text:
            findings.append({"probe": name, "status_code": resp.status_code, "snippet": resp.text[:300]})
    return {"probe_only": True, "findings": findings}
