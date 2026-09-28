"""Local embedding adapter and versioned vectors. Similarity is not permission."""

import hashlib
import math
from importlib.metadata import version
from numbers import Real
from pathlib import Path
from threading import Lock
from typing import Protocol

from pydantic import Field, FiniteFloat, model_validator

from recallguard.models import Memory, Model

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"


class EmbeddingError(Exception):
    """An embedding could not be produced or validated. No lexical fallback."""


class Encoder(Protocol):
    model_id: str
    dimensions: int

    def encode(self, texts: list[str]) -> list[list[float]]: ...


def normalize(values, dimensions: int) -> list[float]:
    values = list(values)
    if len(values) != dimensions or not all(
        isinstance(v, Real) and not isinstance(v, bool) and math.isfinite(v) for v in values
    ):
        raise EmbeddingError("Invalid embedding dimensions or values")
    norm = math.hypot(*values)
    if not math.isfinite(norm) or norm <= 0:
        raise EmbeddingError("Embedding must have a finite, nonzero norm")
    return [float(v / norm) for v in values]


def encode_checked(encoder: Encoder, texts: list[str]) -> list[list[float]]:
    try:
        vectors = list(encoder.encode(texts))
        if len(vectors) != len(texts):
            raise EmbeddingError("Embedding provider returned an incorrect batch size")
        return [normalize(vector, encoder.dimensions) for vector in vectors]
    except Exception:
        # A provider exception can include the input. Surface a fixed message only.
        raise EmbeddingError("Embedding generation failed") from None


def embedding_id(memory_id: str, model_id: str) -> str:
    return hashlib.sha256(f"{memory_id}\0{model_id}".encode()).hexdigest()


class EmbeddingRecord(Model):
    id: str
    memory_id: str
    content_hash: str
    model_id: str
    dimensions: int = Field(ge=1, le=4096)
    vector: list[FiniteFloat] = Field(min_length=1, max_length=4096)

    @model_validator(mode="after")
    def valid_vector(self):
        if len(self.vector) != self.dimensions or math.hypot(*self.vector) <= 0:
            raise ValueError("Invalid stored embedding")
        return self


def make_record(memory: Memory, encoder: Encoder, vector: list[float]) -> EmbeddingRecord:
    return EmbeddingRecord(
        id=embedding_id(memory.id, encoder.model_id),
        memory_id=memory.id,
        content_hash=memory.content_hash,
        model_id=encoder.model_id,
        dimensions=encoder.dimensions,
        vector=normalize(vector, encoder.dimensions),
    )


def find_record(records: dict[str, EmbeddingRecord], memory: Memory, encoder: Encoder):
    record = records.get(embedding_id(memory.id, encoder.model_id))
    if record is None or (
        record.memory_id != memory.id
        or record.model_id != encoder.model_id
        or record.content_hash != memory.content_hash
        or record.dimensions != encoder.dimensions
        or len(record.vector) != encoder.dimensions
    ):
        return None
    if not all(math.isfinite(v) for v in record.vector):
        return None
    if not math.isclose(math.hypot(*record.vector), 1.0, abs_tol=1e-5):
        return None
    return record


class LocalMiniLMEncoder:
    """CPU ONNX model, local inference. Initial model download needs network access.

    Artifact and preprocessing fingerprints prevent comparing different model
    spaces. Token-aware overlapping chunks prevent silent tail truncation.
    """

    dimensions = 384

    def __init__(
        self,
        cache_dir: str | None = None,
        local_files_only: bool = False,
        model_path: str | None = None,
    ):
        try:
            from fastembed import TextEmbedding
            from tokenizers import Tokenizer

            self._model = TextEmbedding(
                model_name=MODEL_NAME,
                cache_dir=cache_dir,
                threads=2,
                local_files_only=local_files_only,
                specific_model_path=model_path,
                providers=["CPUExecutionProvider"],
            )
            # FastEmbed 0.8.1 is pinned: this adapter uses its loaded model directory
            # to bind the identity to actual bytes rather than a mutable model alias.
            directory = Path(self._model.model._model_dir)
            digest = hashlib.sha256()
            for name in (
                "model.onnx",
                "tokenizer.json",
                "config.json",
                "tokenizer_config.json",
                "special_tokens_map.json",
            ):
                path = directory / name
                if name in {"model.onnx", "tokenizer.json"} and not path.is_file():
                    raise EmbeddingError("Required model assets are missing")
                if path.is_file():
                    digest.update(name.encode())
                    with path.open("rb") as file:
                        digest.update(hashlib.file_digest(file, "sha256").digest())
            self._tokenizer = Tokenizer.from_file(str(directory / "tokenizer.json"))
            self._tokenizer.no_truncation()
            self._tokenizer.no_padding()
            self.model_id = (
                f"{MODEL_NAME}:fastembed-{version('fastembed')}:ort-{version('onnxruntime')}:"
                f"tokenizers-{version('tokenizers')}:chunk224-stride192-mean-v1:{digest.hexdigest()}"
            )
            self._lock = Lock()
        except Exception:
            raise EmbeddingError(
                "Local MiniLM initialization failed; install .[semantic] and check the model cache"
            ) from None

    def _chunks(self, text: str) -> list[str]:
        offsets = self._tokenizer.encode(text, add_special_tokens=False).offsets
        if not offsets:
            raise EmbeddingError("Text contains no usable tokens")
        chunks = []
        for start in range(0, len(offsets), 192):
            end = min(start + 224, len(offsets))
            chunks.append(text[offsets[start][0] : offsets[end - 1][1]])
            if end == len(offsets):
                break
        return chunks

    def encode(self, texts: list[str]) -> list[list[float]]:
        with self._lock:
            groups = [self._chunks(text) for text in texts]
            flattened = [chunk for group in groups for chunk in group]
            if not flattened:
                return []
            vectors = [
                normalize(v.tolist(), self.dimensions)
                for v in self._model.embed(flattened, batch_size=32)
            ]
            if len(vectors) != len(flattened):
                raise EmbeddingError("Local model returned an incorrect batch size")
            result = []
            offset = 0
            for group in groups:
                section = vectors[offset : offset + len(group)]
                average = [sum(column) / len(section) for column in zip(*section, strict=True)]
                result.append(normalize(average, self.dimensions))
                offset += len(group)
            return result
