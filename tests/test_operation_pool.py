from fuzzer.graphql.operation_pool import build_operation_pool, unwrap_type


def synthetic_schema():
    return {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "types": [
            {"kind": "OBJECT", "name": "Query", "fields": [{"name": "privateUser", "args": [], "type": {"kind": "OBJECT", "name": "User"}}]},
            {
                "kind": "OBJECT",
                "name": "Mutation",
                "fields": [
                    {
                        "name": "login",
                        "args": [{"name": "username", "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "String"}}}],
                        "type": {"kind": "SCALAR", "name": "String"},
                    }
                ],
            },
            {
                "kind": "OBJECT",
                "name": "User",
                "fields": [
                    {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}},
                    {"name": "email", "type": {"kind": "SCALAR", "name": "String"}},
                ],
            },
        ],
    }


def test_unwrap_type_required():
    name, required = unwrap_type({"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "ID"}})
    assert name == "ID"
    assert required is True


def test_build_operation_pool_and_sensitive_guess():
    ops = build_operation_pool(synthetic_schema())
    names = {op.name for op in ops}
    assert {"privateUser", "login"} <= names
    user_op = next(op for op in ops if op.name == "privateUser")
    assert user_op.sensitive_field_guess
    assert "email" in user_op.selectable_fields
