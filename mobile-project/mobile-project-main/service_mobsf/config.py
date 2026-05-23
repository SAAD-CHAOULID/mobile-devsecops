import os

APK_STORAGE_PATH = os.getenv("APK_STORAGE_PATH", "/apk_storage")
MOBSF_URL        = os.getenv("MOBSF_URL",        "http://172.17.0.2:8000")
MOBSF_API_KEY    = os.getenv("MOBSF_API_KEY",    "")
AGGREGATOR_URL   = os.getenv("AGGREGATOR_URL",   "http://aggregator:8004/results")
