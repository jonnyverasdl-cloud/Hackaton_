import os

# Pin config before any app module loads .env (python-dotenv never overrides a set variable),
# so a local .env can't change test results (audit #7).
os.environ["CORRELATION_WINDOW_MIN"] = "30"
# Tests never call a real model: the narrator runs as the deterministic stub.
os.environ["AI_DISABLED"] = "1"
