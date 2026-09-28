"""Run with python -m recallguard.evaluation; no live-service credentials accepted."""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from recallguard.embeddings import EmbeddingError, LocalMiniLMEncoder
from recallguard.evaluation.runner import EvaluationError, evaluate, load_dataset, markdown


def save(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    # A failed write must not replace an existing report with partial JSON.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as file:
            temporary = Path(file.name)
            file.write(content)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline context-admission evaluation; not an agent attack benchmark."
    )
    parser.add_argument("--dataset", type=Path, default=Path(__file__).with_name("cases-v2.json"))
    parser.add_argument("--mode", choices=["lexical", "semantic"], default="lexical")
    parser.add_argument("--model-cache", default=os.getenv("RECALLGUARD_EMBEDDING_CACHE"))
    parser.add_argument("--model-path", default=os.getenv("RECALLGUARD_EMBEDDING_MODEL_PATH"))
    parser.add_argument(
        "--offline", action="store_true", help="Load cached/provisioned model assets only"
    )
    parser.add_argument(
        "--output", type=Path, help="Write JSON report atomically; otherwise print JSON"
    )
    parser.add_argument("--markdown", type=Path, help="Also write a concise Markdown report")
    args = parser.parse_args(argv)
    try:
        outputs = [p.resolve() for p in (args.output, args.markdown) if p is not None]
        if args.dataset.resolve() in outputs or len(set(outputs)) != len(outputs):
            raise EvaluationError("Input and output paths must be distinct")
        dataset = load_dataset(args.dataset)
        encoder = (
            LocalMiniLMEncoder(args.model_cache, args.offline, args.model_path)
            if args.mode == "semantic"
            else None
        )
        report = evaluate(dataset, encoder)
        text = (
            json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
        )
        if args.output:
            save(args.output, text)
            print(f"Evaluated {len(dataset.cases)} cases; JSON report saved.")
        else:
            print(text, end="")
        if args.markdown:
            save(args.markdown, markdown(report))
    except (EvaluationError, EmbeddingError, OSError) as error:
        # Data validation and adapter errors already have bounded, sanitized messages.
        message = (
            str(error)
            if isinstance(error, (EvaluationError, EmbeddingError))
            else "Could not read input or save reports"
        )
        print(f"Evaluation failed: {message}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
