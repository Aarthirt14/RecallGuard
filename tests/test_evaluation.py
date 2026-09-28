import json
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from recallguard.embeddings import EmbeddingError
from recallguard.evaluation.__main__ import main
from recallguard.evaluation.runner import (
    EvaluationError,
    canonical_hash,
    evaluate,
    fraction,
    load_dataset,
    markdown,
)
from recallguard.evaluation.schema import Dataset

CASES = Path(__file__).parents[1] / "src/recallguard/evaluation/cases.json"


@pytest.fixture
def dataset():
    return load_dataset(CASES)


def test_repeated_runs_have_identical_results_despite_runtime_uuids(dataset):
    first, second = evaluate(dataset), evaluate(dataset)
    assert first == second
    digest = first.pop("result_sha256")
    assert digest == canonical_hash(first)
    assert first["configuration"]["llm_invoked"] is False
    assert first["configuration"]["external_actions_executed"] is False


def test_all_security_invariants_survive_replay(dataset):
    report = evaluate(dataset)
    security = [case for case in report["cases"] if case["category"] == "security"]
    assert security and all(case["methods"]["recallguard"]["case_passed"] for case in security)
    assert any(case["methods"]["unfiltered"]["exposed_forbidden_ids"] for case in security)
    case = next(case for case in report["cases"] if case["id"] == "credential-assignment")
    assert case["write_rejections"] == {"credential": 422}
    assert "credential" in case["methods"]["unfiltered"]["admitted_ids"]


def test_metrics_preserve_explicit_counts_and_known_limitations(dataset):
    report = evaluate(dataset)
    summary = report["summary"]["recallguard"]
    assert summary["forbidden_context_exposure"]["denominator"] == 13
    assert summary["required_context_recall"]["denominator"] == 11
    assert summary["required_candidate_retention"]["denominator"] == 10
    assert summary["required_context_recall"]["numerator"] == sum(
        len(case["methods"]["recallguard"]["required_hits"]) for case in report["cases"]
    )
    text = markdown(report)
    assert "not agent attack-success" in text
    assert "benign-imperative" not in text
    assert "informational-instruction-gap" not in text
    assert "paraphrase-retrieval" in text
    assert "api_key=NOT_A_REAL_CREDENTIAL" not in json.dumps(report)


def test_filter_before_top_k_and_minimal_ablations(dataset):
    case = next(case for case in dataset.cases if case.id == "filter-before-top-k")
    single = dataset.model_copy(update={"cases": [case]})
    report = evaluate(single)
    methods = report["cases"][0]["methods"]
    assert methods["unfiltered"]["admitted_ids"] == ["payload"]
    assert methods["text_filter"]["admitted_ids"] == ["useful"]
    assert methods["recallguard"]["admitted_ids"] == ["useful"]
    assert report["summary"]["recallguard"]["required_context_recall"] == fraction(1, 1)
    assert report["summary"]["unfiltered"]["forbidden_context_exposure"] == fraction(1, 1)


def test_missing_candidates_are_not_counted_as_detector_success(dataset):
    raw = dataset.model_dump(mode="json")
    raw["cases"] = [raw["cases"][0]]
    raw["cases"][0]["query"]["query"] = "unrelatedqueryterm"
    report = evaluate(Dataset.model_validate(raw))
    stats = report["summary"]["recallguard"]
    assert stats["forbidden_context_exposure"] == fraction(0, 1)
    assert stats["forbidden_candidate_coverage"] == fraction(0, 1)
    assert stats["required_context_recall"] == fraction(0, 0)
    assert fraction(0, 0)["rate"] is None
    assert "n/a (0 denominator)" in markdown(report)


def test_stable_ties_use_case_ids_not_generated_uuids(dataset):
    raw = dataset.model_dump(mode="json")
    case = raw["cases"][0]
    case["operations"] = [
        {"op": "write", "id": mid, "memory": {"content": "Orion", "source_id": "external"}}
        for mid in ["z-last", "a-first"]
    ]
    case["query"] = {"query": "Orion", "limit": 1}
    case["required_ids"], case["forbidden_ids"] = ["a-first"], []
    raw["cases"] = [case]
    for _ in range(3):
        report = evaluate(Dataset.model_validate(raw))
        assert all(m["admitted_ids"] == ["a-first"] for m in report["cases"][0]["methods"].values())


@pytest.mark.parametrize(
    "mutation",
    [
        lambda case: case.update(required_ids=["unknown"]),
        lambda case: case.update(required_ids=case["forbidden_ids"]),
        lambda case: case.update(forbidden_ids=[]),
        lambda case: case["operations"][0]["memory"].update(source_id="missing"),
        lambda case: case["operations"].append(deepcopy(case["operations"][0])),
        lambda case: case["operations"].insert(0, {"op": "revoke", "memory_id": "account"}),
        lambda case: case["query"].update(mode="semantic"),
        lambda case: case["sources"].append(deepcopy(case["sources"][0])),
    ],
)
def test_invalid_case_references_and_labels_are_rejected(dataset, mutation):
    raw = dataset.model_dump(mode="json")
    mutation(raw["cases"][0])
    with pytest.raises(ValidationError):
        Dataset.model_validate(raw)


def test_unexpected_policy_error_aborts_instead_of_inflating_safety(dataset):
    raw = dataset.model_dump(mode="json")
    raw["cases"] = [raw["cases"][0]]
    raw["cases"][0]["operations"][0]["memory"]["source_id"] = "trusted"
    with pytest.raises(EvaluationError, match="failed unexpectedly"):
        evaluate(Dataset.model_validate(raw))


def test_missing_expected_rejection_is_a_run_error(dataset):
    raw = dataset.model_dump(mode="json")
    raw["cases"] = [raw["cases"][0]]
    raw["cases"][0]["operations"][0]["expected_error"] = 422
    with pytest.raises(EvaluationError, match="expected write rejection did not occur"):
        evaluate(Dataset.model_validate(raw))


def test_semantic_provider_failure_is_not_a_successful_defense(dataset):
    class BrokenEncoder:
        model_id = "test-broken"
        dimensions = 2

        def encode(self, texts):
            raise RuntimeError("private content should not escape")

    with pytest.raises(EmbeddingError) as error:
        evaluate(dataset, BrokenEncoder())
    assert "private content" not in str(error.value)


def test_semantic_mode_uses_same_vectors_and_policy_for_all_methods(dataset):
    class Encoder:
        model_id = "test-model"
        dimensions = 2

        def __init__(self):
            self.texts = []

        def encode(self, texts):
            self.texts.extend(texts)
            return [[1.0, 0.0] for _ in texts]

    encoder = Encoder()
    report = evaluate(dataset, encoder)
    assert report["configuration"]["model_id"] == "test-model"
    assert len(encoder.texts) == len(set(encoder.texts))
    assert all(
        c["methods"]["recallguard"]["case_passed"]
        for c in report["cases"]
        if c["category"] == "security"
    )


def test_cli_writes_reproducible_json_and_markdown(tmp_path, capsys):
    output, text = tmp_path / "report.json", tmp_path / "report.md"
    args = ["--dataset", str(CASES), "--output", str(output), "--markdown", str(text)]
    assert main(args) == 0
    first = output.read_bytes()
    assert main(args) == 0
    assert output.read_bytes() == first
    assert "RecallGuard context-admission evaluation" in text.read_text()
    assert "JSON report saved" in capsys.readouterr().out


def test_cli_refuses_overwriting_input_or_sharing_output_paths(tmp_path, capsys):
    dataset = tmp_path / "data.json"
    dataset.write_bytes(CASES.read_bytes())
    original = dataset.read_bytes()
    assert main(["--dataset", str(dataset), "--output", str(dataset)]) == 2
    assert dataset.read_bytes() == original
    assert main(["--output", str(tmp_path / "out"), "--markdown", str(tmp_path / "out")]) == 2
    assert "distinct" in capsys.readouterr().err


def test_invalid_dataset_leaves_existing_report_intact(tmp_path, capsys):
    dataset, output = tmp_path / "bad.json", tmp_path / "out.json"
    dataset.write_text('{"private-input-marker": 1}')
    output.write_text("existing report")
    assert main(["--dataset", str(dataset), "--output", str(output)]) == 2
    assert output.read_text() == "existing report"
    assert "private-input-marker" not in capsys.readouterr().err


def test_dataset_size_bound(tmp_path):
    path = tmp_path / "large.json"
    with path.open("wb") as file:
        file.truncate(4 * 1024 * 1024 + 1)
    with pytest.raises(EvaluationError, match="4 MiB"):
        load_dataset(path)


@pytest.mark.parametrize("counts", [(2, 1), (-1, 1), (1, 0)])
def test_impossible_metric_counts_are_rejected(counts):
    with pytest.raises(ValueError, match="Metric counts"):
        fraction(*counts)


def test_expanded_suite_preserves_utility_and_reports_residual_limits():
    report = evaluate(load_dataset(CASES.with_name("hardening.json")))
    assert len(report["cases"]) == 29
    for case in report["cases"]:
        assert case["methods"]["recallguard"]["case_passed"] == (case["category"] != "limitation")
    summary = report["summary"]["recallguard"]
    assert summary["case_checks_passed"] == fraction(27, 29)
    assert summary["forbidden_candidate_coverage"] == fraction(20, 20)
    assert summary["forbidden_context_exposure"] == fraction(1, 20)
    assert summary["required_context_recall"] == fraction(27, 28)
    assert report["configuration"]["text_filter_policy"] == "frozen-v0.5-raw-content"
    assert "screening_sha256" in report["software"]
