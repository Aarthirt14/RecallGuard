"""Generate local secrets without printing them or overwriting an existing .env."""

import os
import secrets
from pathlib import Path

path = Path(__file__).resolve().parents[1] / ".env"
try:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except FileExistsError:
    raise SystemExit(".env already exists; left unchanged.") from None
with os.fdopen(descriptor, "w") as output:
    output.write(
        f"RECALLGUARD_AGENT_KEY={secrets.token_hex(32)}\n"
        f"RECALLGUARD_REVIEWER_KEY={secrets.token_hex(32)}\n"
        f"NEO4J_PASSWORD={secrets.token_hex(24)}\n"
    )
print("Created .env. Keep the reviewer key outside the agent process.")
