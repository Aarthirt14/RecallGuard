# MPBench attribution

External corpus: **MPBench: Memory Poisoning Benchmark for LLM Agents**.

Authors credited by the upstream README: Pritam Dash, Tongyu Ge, Aditi Jain, Tanmay Shah, and Zhiwei Shang.

- Repository: https://github.com/Digital-Trust-Lab/mp-bench
- Pinned revision: `6886880a7c29625e0109e0ad91d0e095029f1577`
- Paper: *From Untrusted Input to Trusted Memory: A Systematic Study of Memory Poisoning Attacks in LLM Agents* (AIWILD @ ICML 2026), https://arxiv.org/abs/2606.04329
- Repository license: Apache License 2.0. The adjacent LICENSE is an unmodified copy from the pinned revision. No upstream NOTICE file is present at that revision.

RecallGuard does not bundle the corpus rows or execute upstream code. Its pin manifest and audit reports refer to the original files. The separately authored adapter performs a different, explicitly limited external-material admission audit, not a reproduction of the paper's agent evaluation. It preserves original payload strings and raw category names, decodes the one line containing adjacent JSON objects, explicitly normalizes seven string boolean annotations, and identifies rows by split plus original ID because some benign IDs use an ADV prefix. No expected memory is injected as an agent output.
