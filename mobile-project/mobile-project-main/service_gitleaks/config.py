import os

REPOS_STORAGE_PATH  = os.getenv("REPOS_STORAGE_PATH",  "/repos_storage")
AGGREGATOR_URL      = os.getenv("AGGREGATOR_URL",       "http://aggregator:8004/results")
# Args supplémentaires à passer à gitleaks (ex: "--config /app/gitleaks.toml")
GITLEAKS_EXTRA_ARGS = os.getenv("GITLEAKS_EXTRA_ARGS", "").split() or []
