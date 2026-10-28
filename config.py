"""GarudaX settings. Values can be set in backend/.env (copy .env.example) or as environment variables."""
import os
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent


def _load_dotenv(path):
    """Tiny .env reader (KEY=VALUE lines) so no extra package is needed."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_dotenv(BACKEND_DIR / ".env")


def _int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _float(name, default):
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


# ---- uploads ----
UPLOADS = BACKEND_DIR / "uploads"
OUTBOX = BACKEND_DIR / "outbox"          # emails are saved here when SMTP is not configured
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}
MAX_PHOTO_BYTES = 12 * 1024 * 1024

# ---- AI validation ----
MIN_AI_CONFIDENCE = _float("GARUDAX_MIN_AI_CONFIDENCE", 0.25)   # at/above this the AI result is trusted automatically
# "AI unsure" band: if the best detection is between AI_REVIEW_MIN_CONFIDENCE and MIN_AI_CONFIDENCE, the complaint is
# saved but flagged for the Municipal Authority to check the photo manually. Nothing detected (confidence 0) is always rejected.
AI_REVIEW_ENABLED = os.environ.get("GARUDAX_AI_REVIEW", "1") == "1"
AI_REVIEW_MIN_CONFIDENCE = _float("GARUDAX_AI_REVIEW_MIN_CONFIDENCE", 0.03)

# ---- duplicate / repeated photo detection ----
DUPLICATE_RADIUS_M = _float("GARUDAX_DUPLICATE_RADIUS_M", 30)  # same damage type within this distance = duplicate
DUPLICATE_ANY_TYPE_RADIUS_M = _float("GARUDAX_DUPLICATE_ANY_RADIUS_M", 10)
DUPLICATE_WINDOW_DAYS = _int("GARUDAX_DUPLICATE_WINDOW_DAYS", 30)
SIMILAR_PHOTO_MAX_DISTANCE = _int("GARUDAX_SIMILAR_PHOTO_DISTANCE", 5)   # dHash bits; 0 = identical picture
MAX_PHOTO_AGE_HOURS = _int("GARUDAX_MAX_PHOTO_AGE_HOURS", 48)          # checked only when the photo has EXIF date

# ---- escalation ----
ESCALATION_DAYS = _int("GARUDAX_ESCALATION_DAYS", 15)
ESCALATION_CHECK_MINUTES = _int("GARUDAX_ESCALATION_CHECK_MINUTES", 30)

# ---- sessions & passwords ----
SESSION_DAYS = _int("GARUDAX_SESSION_DAYS", 7)
MAX_FAILED_LOGINS = _int("GARUDAX_MAX_FAILED_LOGINS", 5)
LOCKOUT_MINUTES = _int("GARUDAX_LOCKOUT_MINUTES", 15)
RESET_CODE_MINUTES = _int("GARUDAX_RESET_CODE_MINUTES", 15)
RESET_MAX_ATTEMPTS = 5
RESET_MAX_REQUESTS_PER_WINDOW = 3

# ---- email (SMTP). Leave GARUDAX_SMTP_HOST empty to save emails in backend/outbox instead ----
SMTP_HOST = os.environ.get("GARUDAX_SMTP_HOST", "").strip()
SMTP_PORT = _int("GARUDAX_SMTP_PORT", 587)
SMTP_USER = os.environ.get("GARUDAX_SMTP_USER", "").strip()
SMTP_PASSWORD = os.environ.get("GARUDAX_SMTP_PASSWORD", "").strip()
SMTP_FROM = os.environ.get("GARUDAX_SMTP_FROM", SMTP_USER or "garudax@localhost").strip()
SMTP_USE_SSL = os.environ.get("GARUDAX_SMTP_SSL", "0") == "1"   # 1 for port 465
AUTHORITY_ALERT_EMAIL = os.environ.get("GARUDAX_AUTHORITY_EMAIL", "").strip()  # optional extra address for escalation alerts
