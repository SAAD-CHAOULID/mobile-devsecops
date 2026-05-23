import os

GITHUB_SECRET    = os.getenv("GITHUB_SECRET", "change_me")
ADMIN_API_KEY    = os.getenv("ADMIN_API_KEY", "admin_secret_key")
REPOS_STORAGE    = os.getenv("REPOS_STORAGE", "/repos_storage")
APK_STORAGE      = os.getenv("APK_STORAGE",   "/apk_storage")
OLLAMA_URL       = os.getenv("OLLAMA_URL",     "http://ollama:11434")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")

INTERNAL_SERVICES = {
    "mobsf":       os.getenv("MOBSF_URL",       "http://service_mobsf:8001"),
    "gitleaks":    os.getenv("GITLEAKS_URL",     "http://service_gitleaks:8002"),
    "syft":        os.getenv("SYFT_URL",         "http://service_syft:8003"),
    "androguard":  os.getenv("ANDROGUARD_URL",   "http://service_androguard:8004"),
    "virustotal":  os.getenv("VIRUSTOTAL_URL",   "http://service_virustotal:8005"),
    "permissions": os.getenv("PERMISSIONS_URL",  "http://service_permissions:8006"),
    "network":     os.getenv("NETWORK_URL",      "http://service_network:8007"),
    "obfuscation": os.getenv("OBFUSCATION_URL",  "http://service_obfuscation:8008"),
    "ssl":         os.getenv("SSL_URL",           "http://service_ssl:8009"),
    "aggregator":  os.getenv("AGGREGATOR_URL",    "http://service_aggregator:8011"), 
}
GROK_API_KEY = os.getenv("GROK_API_KEY", "")
