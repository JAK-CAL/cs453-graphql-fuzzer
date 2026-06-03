from __future__ import annotations

import argparse
import sys

from fuzzer.config import load_config
from fuzzer.evaluation.report import write_report
from fuzzer.runners import auth_mutation_only, fsm_ga, query_shape_only, random_graphql, random_sequence
from fuzzer.runners.common import prepare_run


RUNNERS = {
    "fsm-ga": fsm_ga.run,
    "random-graphql": random_graphql.run,
    "random-sequence": random_sequence.run,
    "auth-only": auth_mutation_only.run,
    "query-shape-only": query_shape_only.run,
}


def cmd_discover(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    result_dir, _storage, _client, _schema, operations, _server_model = prepare_run(config)
    print(f"discovery complete: {len(operations)} operations -> {result_dir}")
    return 0


def cmd_fuzz(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    runner = RUNNERS[args.mode]
    result = runner(config)
    print(
        f"fuzz complete: findings={len(result['findings'])} "
        f"states={result['coverage'].get('state_coverage', 0)} "
        f"transitions={result['coverage'].get('transition_coverage', 0)}"
    )
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    metrics = write_report(args.result_dir)
    print(f"evaluation complete: total_findings={metrics['total_findings']} unique_findings={metrics['unique_findings']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="FSM-guided GraphQL security fuzzer")
    sub = parser.add_subparsers(dest="command", required=True)
    discover = sub.add_parser("discover", help="run GraphQL introspection/probing")
    discover.add_argument("--config", required=True)
    discover.set_defaults(func=cmd_discover)
    fuzz = sub.add_parser("fuzz", help="run fuzzer")
    fuzz.add_argument("--config", required=True)
    fuzz.add_argument("--mode", choices=sorted(RUNNERS), default="fsm-ga")
    fuzz.set_defaults(func=cmd_fuzz)
    evaluate = sub.add_parser("evaluate", help="summarize a result directory")
    evaluate.add_argument("--result-dir", required=True)
    evaluate.set_defaults(func=cmd_evaluate)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
