# Semantic retrieval

RecallGuard can use local MiniLM embeddings to retrieve paraphrases without shared query words. Similarity determines relevance only. Every candidate still passes the existing lifecycle, ancestry, conflict, and exact action/target approval checks before the allowed-result limit is applied. The procurement agent uses the configured retriever automatically; its independent execution gate remains in place.

## Enable it

The default installation remains lexical and needs no model download. For semantic retrieval:

```bash
python -m pip install -e '.[dev,semantic]'
export RECALLGUARD_RETRIEVAL_MODE=semantic
export RECALLGUARD_EMBEDDING_CACHE="$PWD/.model-cache"
# Set the API keys and storage configuration as described in README.md.
python -m uvicorn recallguard.api:create_app --factory --host 127.0.0.1 --port 8000
```

PowerShell users can set the same variables with `$env:NAME = 'value'`.

With Docker:

```bash
python scripts/init_env.py
docker compose -f compose.yaml -f compose.semantic.yaml up --build
```

The override installs the optional model runtime and retains downloaded assets in a named volume. Startup downloads the ONNX MiniLM model on first use. Text inference runs on the local CPU; memory and query text are not sent to a hosted embedding API. Model downloads still contact the model host. Startup fails if the selected model cannot load; there is no silent lexical fallback.

For offline operation, provision the model assets first, set `RECALLGUARD_EMBEDDING_OFFLINE=1`, and retain the cache. `RECALLGUARD_EMBEDDING_MODEL_PATH` can point to a provisioned model directory containing `model.onnx`, `tokenizer.json`, and the accompanying configuration files. Treat model assets and the encoder implementation as trusted deployment inputs. The model identity fingerprints the loaded files and runtime versions; it detects incompatible vector spaces, not model authenticity.

## Existing memories and model upgrades

New memories and their vectors commit together. Older records need backfill. Using the **reviewer** API key:

1. `GET /embeddings/status` reports the current `model_id`, dimensions, eligible nonrevoked memories, indexed count, and remaining count.
2. `POST /embeddings/reindex` with `{"limit":32}` indexes one batch. Repeat until `remaining` is zero. Limits are 1–256.
3. The operation skips already indexed records and memories revoked while inference was running. A failed batch writes no embeddings or indexing audit events.

A model or preprocessing change produces a different identity. Existing vectors remain stored for auditability but cannot be compared with the new model. Repeat backfill after upgrades. Quarantined memories can have vectors, but policy blocks them from allowed context. Revocation is logical restriction, not physical deletion, including for embeddings.

## Query contract

```json
{"query":"When will my parcel arrive?","mode":"semantic","min_score":0.25,"limit":5,"action":"inform"}
```

Omitting `mode` uses the deployment default. An explicit `mode:"lexical"` uses token overlap. Requesting semantic mode without an encoder returns HTTP 503. Invalid vector generation also returns 503 without fallback.

Results contain:

- `allowed`: only currently permitted memories.
- `blocked`: restricted candidate IDs and reasons, without their text or scores.
- `scores`: relevance scores for allowed memories only; cosine similarity in semantic mode, token overlap in lexical mode.
- `mode` and `model_id`: retrieval method and, for semantic mode, the exact model identity.
- `unindexed_count`: nonrevoked memories without a compatible vector. A nonzero count means semantic coverage is incomplete; these records are excluded rather than silently mixed with another model.

`min_score` is a semantic cosine threshold from -1 to 1. Its default 0.25 is a starting configuration, not a calibrated confidence or factual-correctness score. It is ignored by lexical search. Lower thresholds can retrieve more irrelevant context; they cannot override security policy.

## Storage and scope

Vectors are server-owned records bound to memory ID, content hash, model identity, and dimensions. API clients cannot submit vectors. MiniLM produces 384 dimensions. Long text is split into overlapping 224-token chunks with stride 192; normalized chunk vectors are averaged and normalized again. This includes the tail of long memories, though averaging can dilute a short relevant passage.

This milestone performs **exact cosine search in Python**, loading records from the transactional store. Neo4j persists vectors as typed JSON records; this is not a Neo4j ANN vector index. Model inference occurs outside retryable database transactions; final eligibility checks and retrieval auditing happen inside the transaction. The current full-workspace scan and copy/serialization costs limit this implementation to small research datasets. Indexed search, pagination, vector cleanup, resource quotas, multilingual evaluation, and a reviewer dashboard remain future work.

## Verification

The default suite uses deterministic encoder doubles to test policy, transaction failure, stale vectors, model changes, backfill, and revocation races without downloads. Neo4j integration covers vector persistence across reconnects. To run the actual CPU model smoke test:

```bash
python -m pip install -e '.[dev,semantic]'
RECALLGUARD_TEST_MODEL=1 python -m pytest -q -m model
```

GitHub Actions runs the model smoke in a separate job. It checks a paraphrase with no shared query words, local vector shape and normalization, long-text chunk coverage, and payment/revocation restrictions. This is a functional smoke test, not a retrieval-accuracy or attack-success benchmark.

References: [FastEmbed](https://github.com/qdrant/fastembed), [MiniLM model card](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2).
