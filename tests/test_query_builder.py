from fuzzer.ga.chromosome import QueryShape
from fuzzer.graphql.query_builder import build_graphql_document
from fuzzer.graphql.schema_types import Argument, Operation


def test_basic_query_generation():
    op = Operation("user", "query", [Argument("id", "ID", True)], "User", ["id", "email"])
    query, variables = build_graphql_document(op, {"id": "1"}, QueryShape())
    assert "query Fuzz" in query
    assert "user(id: $id)" in query
    assert "email" in query
    assert variables == {"id": "1"}


def test_mutation_generation():
    op = Operation("createPost", "mutation", [Argument("title", "String")], "Post", ["id"])
    query, _ = build_graphql_document(op, {"title": "t"}, QueryShape())
    assert query.startswith("mutation")


def test_alias_duplicate_and_batch_generation():
    op = Operation("posts", "query", [], "Post", ["id"], {"author": "User"})
    query, _ = build_graphql_document(op, {}, QueryShape(alias_count=2, duplicate_fields=2, depth=2))
    assert "a0:" in query and "a1:" in query
    assert query.count("id") >= 2
    batch, variables = build_graphql_document(op, {}, QueryShape(batch=True, batch_size=3))
    assert len(batch) == 3
    assert variables == {}
