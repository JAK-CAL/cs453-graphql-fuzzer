from fuzzer.ga.chromosome import Chromosome
from fuzzer.storage.findings import collect_findings


def test_collect_findings_dedupes_auth_modes_for_same_identity():
    chrom = Chromosome([])
    chrom.findings = [
        {
            "finding_type": "AUTH_BYPASS_CANDIDATE",
            "operation": "user",
            "transition": "protected_query_without_token",
            "auth_mode": "no_token",
            "evidence": {"matched_keywords": ["token"]},
        },
        {
            "finding_type": "AUTH_BYPASS_CANDIDATE",
            "operation": "user",
            "transition": "protected_query_with_low_privilege",
            "auth_mode": "low_privilege",
            "evidence": {"matched_keywords": ["token"]},
        },
    ]

    assert len(collect_findings([chrom])) == 1
