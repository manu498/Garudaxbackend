"""GarudaX REST API: secure sign-in, AI-verified citizen complaints, authority assignment,
repair evidence (before/after photos), priority & escalation, contribution score and PDF/email reports."""
import secrets
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path

from flask import Flask, g, jsonify, request, send_file, send_from_directory
from PIL import Image, UnidentifiedImageError
from werkzeug.security import check_password_hash, generate_password_hash

import config
from database import connect, init_db
from detector import detect_damage
from mailer import send_email, smtp_configured
from photos import dhash_hex, distance_m, exif_taken_at, hamming, sha256_hex
from reports import build_complaint_pdf
from security import create_session, fail, hash_token, password_problem, require_auth, revoke_all_sessions

config.UPLOADS.mkdir(exist_ok=True)
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = config.MAX_PHOTO_BYTES + 1024 * 1024
init_db()

OPEN_STATUSES_SQL = "('Completed','Rejected')"
ROLE_NAMES = {"citizen": "Citizen", "authority": "Municipal Authority", "worker": "Repair Worker"}
DAMAGE_WEIGHT = {"pothole": 40, "manhole": 35, "crack": 25}


# ------------------------------------------------------------------ helpers
def local_time(utc_text):
    """SQLite stores UTC; show it in the server's local time (IST on an Indian PC)."""
    if not utc_text:
        return None
    try:
        dt = datetime.strptime(str(utc_text)[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).astimezone()
        return dt.strftime("%d %b %Y, %I:%M %p")
    except ValueError:
        return str(utc_text)


def user_by_id(db, user_id):
    return db.execute("SELECT id,name,email,phone,role FROM users WHERE id=?", (user_id,)).fetchone()


def compute_priority(c):
    """Emergency prioritisation: damage type, AI confidence, age, extra reports, citizen urgency, 15-day escalation."""
    score = DAMAGE_WEIGHT.get(str(c.get("damage_type") or "").lower(), 20)
    score += round((c.get("confidence") or 0) * 0.2)
    score += min(int(c.get("age_days") or 0) * 2, 30)
    score += min(int(c.get("support_count") or 0) * 5, 25)
    score += 15 if c.get("citizen_urgent") else 0
    score += 40 if c.get("high_emergency") else 0
    if c.get("status") in ("Completed", "Rejected"):
        label = "Closed"
    elif score >= 90:
        label = "Critical"
    elif score >= 65:
        label = "High"
    elif score >= 45:
        label = "Medium"
    else:
        label = "Low"
    return score, label


COMPLAINT_SELECT = """SELECT c.*, citizen.name AS citizen_name, citizen.email AS citizen_email,
        worker.name AS worker_name, worker.email AS worker_email,
        CAST(julianday('now') - julianday(c.created_at) AS INTEGER) AS age_days
    FROM complaints c JOIN users citizen ON citizen.id=c.citizen_id
    LEFT JOIN users worker ON worker.id=c.assigned_worker_id"""


def complaint_dict(row, public=True):
    c = dict(row)
    c["priority_score"], c["priority_label"] = compute_priority(c)
    c["photo_url"] = "/uploads/" + c["photo_filename"] if c.get("photo_filename") else None
    c["before_photo_url"] = "/uploads/" + c["before_photo_filename"] if c.get("before_photo_filename") else None
    c["after_photo_url"] = "/uploads/" + c["after_photo_filename"] if c.get("after_photo_filename") else None
    c["created_at_raw"] = c.get("created_at")
    for key in ("created_at", "updated_at", "completed_at", "emergency_escalated_at"):
        c[key] = local_time(c.get(key))
    if public:
        for key in [k for k in c if k.endswith("_sha256") or k.endswith("_dhash") or k.endswith("_filename")] + ["citizen_email", "worker_email"]:
            c.pop(key, None)
    return c


def load_complaint(db, complaint_id, public=True):
    row = db.execute(COMPLAINT_SELECT + " WHERE c.id=?", (complaint_id,)).fetchone()
    return complaint_dict(row, public) if row else None


def can_view(user, c):
    return (user["role"] == "authority"
            or (user["role"] == "citizen" and c["citizen_id"] == user["id"])
            or (user["role"] == "worker" and c["assigned_worker_id"] == user["id"]))


def load_history(db, complaint_id):
    rows = db.execute("""SELECT r.status, r.note, r.created_at, u.name AS actor_name, u.role AS actor_role
                         FROM repair_updates r JOIN users u ON u.id=r.actor_id
                         WHERE r.complaint_id=? ORDER BY r.id""", (complaint_id,)).fetchall()
    return [dict(r, created_at=local_time(r["created_at"]), actor_role=ROLE_NAMES.get(r["actor_role"], r["actor_role"])) for r in rows]


def add_history(db, complaint_id, actor_id, status, note):
    db.execute("INSERT INTO repair_updates(complaint_id,actor_id,status,note) VALUES(?,?,?,?)", (complaint_id, actor_id, status, note))


def citizen_score(db, citizen_id):
    """Contribution score: +10 per verified report (AI-confirmed or approved by the authority), +15 when it is repaired, +2 per confirmation of
    another citizen's report, -5 per report rejected by the authority."""
    counts = db.execute("""SELECT
            SUM(CASE WHEN status!='Rejected' AND ai_review=0 THEN 1 ELSE 0 END) AS accepted,
            SUM(CASE WHEN status='Completed' THEN 1 ELSE 0 END) AS repaired,
            SUM(CASE WHEN status='Rejected' THEN 1 ELSE 0 END) AS rejected,
            COUNT(*) AS total
        FROM complaints WHERE citizen_id=?""", (citizen_id,)).fetchone()
    confirmations = db.execute("SELECT COUNT(*) FROM complaint_supporters WHERE citizen_id=?", (citizen_id,)).fetchone()[0]
    accepted, repaired, rejected = counts["accepted"] or 0, counts["repaired"] or 0, counts["rejected"] or 0
    score = max(0, accepted * 10 + repaired * 15 + confirmations * 2 - rejected * 5)
    level = "Garuda Champion" if score >= 150 else "Road Guardian" if score >= 50 else "Road Watcher"
    next_at = 50 if score < 50 else 150 if score < 150 else None
    return {"score": score, "level": level, "next_level_at": next_at, "reports": counts["total"] or 0,
            "accepted": accepted, "repaired": repaired, "rejected": rejected, "confirmations": confirmations}


def read_photo(field="photo"):
    """Validate an uploaded photo. Returns (bytes, extension, None) or (None, None, error_response)."""
    photo = request.files.get(field)
    if photo is None or not photo.filename:
        return None, None, fail("Take a photo with the camera to continue.")
    extension = Path(photo.filename).suffix.lower()
    if extension not in config.ALLOWED_EXTENSIONS:
        return None, None, fail("Use a JPG, PNG or WEBP photo.")
    payload = photo.read(config.MAX_PHOTO_BYTES + 1)
    if not payload or len(payload) > config.MAX_PHOTO_BYTES:
        return None, None, fail("Photo is empty or exceeds the 12 MB limit.")
    try:
        with Image.open(BytesIO(payload)) as image:
            image.verify()
    except Exception:  # includes UnidentifiedImageError and missing optional codecs
        return None, None, fail("The selected file is not a valid image.")
    return payload, extension, None


def photo_too_old(payload):
    taken = exif_taken_at(payload)
    if taken is None:
        return False
    return datetime.now() - taken > timedelta(hours=config.MAX_PHOTO_AGE_HOURS)


def find_repeated_photo(db, sha, dh, exclude_id=None):
    """Repeated-photo detection: exact copy (SHA-256) or near-identical picture (dHash) of ANY photo already
    stored (complaint, before or after photo). Returns (complaint_id, kind) or None."""
    for col_sha, col_dh in (("photo_sha256", "photo_dhash"), ("before_photo_sha256", "before_photo_dhash"), ("after_photo_sha256", "after_photo_dhash")):
        row = db.execute(f"SELECT id FROM complaints WHERE {col_sha}=? AND id IS NOT ?", (sha, exclude_id)).fetchone()
        if row:
            return row["id"], "exact"
    for row in db.execute("SELECT id, photo_dhash, before_photo_dhash, after_photo_dhash FROM complaints WHERE id IS NOT ?", (exclude_id,)):
        for value in (row["photo_dhash"], row["before_photo_dhash"], row["after_photo_dhash"]):
            if value and hamming(value, dh) <= config.SIMILAR_PHOTO_MAX_DISTANCE:
                return row["id"], "similar"
    return None


def find_duplicate_location(db, lat, lon, damage_type):
    rows = db.execute(f"""SELECT id, citizen_id, latitude, longitude, damage_type FROM complaints
                          WHERE status NOT IN {OPEN_STATUSES_SQL}
                          AND julianday('now') - julianday(created_at) <= ?""", (config.DUPLICATE_WINDOW_DAYS,)).fetchall()
    best = None
    for r in rows:
        d = distance_m(lat, lon, r["latitude"], r["longitude"])
        same_type = str(r["damage_type"]).lower() == str(damage_type).lower()
        if (same_type and d <= config.DUPLICATE_RADIUS_M) or d <= config.DUPLICATE_ANY_TYPE_RADIUS_M:
            if best is None or d < best[1]:
                best = (r, d)
    return best


def remove_quietly(path):
    """Delete a temporary file. On Windows, antivirus or the AI library can keep it locked for a moment;
    that must never fail the request."""
    for _ in range(5):
        try:
            Path(path).unlink(missing_ok=True)
            return
        except OSError:
            time.sleep(0.2)
    print(f"[GarudaX] Could not delete temporary file {path} (it will be ignored).")


def save_photo(payload, extension):
    name = uuid.uuid4().hex + extension
    (config.UPLOADS / name).write_bytes(payload)
    return name


def email_complaint_pdf(complaint_id, to_address, subject, intro):
    """Build the complaint PDF and email it (runs in a background thread)."""
    def job():
        try:
            with connect() as db:
                c = load_complaint(db, complaint_id, public=False)
                history = load_history(db, complaint_id)
            pdf = build_complaint_pdf(c, history)
            body = (f"{intro}\n\nComplaint: #GX-{c['id']:05d}\nStatus: {c['status']}\nPriority: {c['priority_label']}\n"
                    f"AI detection: {c.get('damage_type')} ({c.get('confidence')}%)\n"
                    f"Location: https://maps.google.com/?q={c['latitude']},{c['longitude']}\n\n"
                    "The full complaint report with photos and timeline is attached as a PDF.\n\n— GarudaX")
            send_email(to_address, subject, body, [(f"GarudaX_Complaint_GX-{c['id']:05d}.pdf", pdf, "application/pdf")], background=False)
        except Exception as exc:
            print(f"[GarudaX mail] Could not prepare PDF email for complaint {complaint_id}: {exc}")
    threading.Thread(target=job, daemon=True).start()
    return "sending" if smtp_configured() else "saved_to_outbox"


# ------------------------------------------------------------------ escalation (automation)
def run_escalation():
    """Flag complaints still unresolved after ESCALATION_DAYS as High Emergency, log it and alert the authority."""
    note = f"Automatically escalated to High Emergency after {config.ESCALATION_DAYS} days without completion"
    with connect() as db:
        rows = db.execute(f"""SELECT id, citizen_id FROM complaints WHERE high_emergency=0 AND status NOT IN {OPEN_STATUSES_SQL}
                              AND julianday('now') - julianday(created_at) >= ?""", (config.ESCALATION_DAYS,)).fetchall()
        if not rows:
            return 0
        ids = [r["id"] for r in rows]
        for r in rows:
            db.execute("UPDATE complaints SET high_emergency=1, emergency_escalated_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?", (r["id"],))
            add_history(db, r["id"], r["citizen_id"], "High Emergency", note)
        recipients = [u["email"] for u in db.execute("SELECT email FROM users WHERE role='authority'")]
    if config.AUTHORITY_ALERT_EMAIL:
        recipients.append(config.AUTHORITY_ALERT_EMAIL)
    listing = "\n".join(f"  • Complaint #GX-{i:05d}" for i in ids)
    for to in sorted(set(recipients)):
        send_email(to, f"GarudaX alert: {len(ids)} complaint(s) escalated to High Emergency",
                   f"The following complaints are still unresolved after {config.ESCALATION_DAYS} days and are now HIGH EMERGENCY:\n\n{listing}\n\nPlease assign or verify them immediately.\n\n— GarudaX")
    print(f"[GarudaX] Escalated {len(ids)} complaint(s) to High Emergency: {ids}")
    return len(ids)


_scheduler_started = False
_scheduler_lock = threading.Lock()


def start_scheduler():
    """Background job: checks for overdue complaints every ESCALATION_CHECK_MINUTES, even if nobody opens the app."""
    global _scheduler_started
    with _scheduler_lock:
        if _scheduler_started:
            return
        _scheduler_started = True

    def loop():
        while True:
            try:
                run_escalation()
            except Exception as exc:
                print(f"[GarudaX] Escalation check failed: {exc}")
            time.sleep(max(1, config.ESCALATION_CHECK_MINUTES) * 60)
    threading.Thread(target=loop, daemon=True, name="garudax-escalation").start()


@app.before_request
def _ensure_scheduler():
    start_scheduler()


# ------------------------------------------------------------------ health & auth
@app.get("/api/health")
def health():
    return jsonify({"ok": True, "service": "GarudaX API", "database": "SQLite", "email": "smtp" if smtp_configured() else "outbox"})


@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    phone = str(data.get("phone", "")).strip()
    password = str(data.get("password", ""))
    if not name or "@" not in email or "." not in email.split("@")[-1]:
        return fail("Enter your name and a valid email address.")
    problem = password_problem(password)
    if problem:
        return fail(problem)
    try:
        with connect() as db:
            cursor = db.execute("INSERT INTO users(name,email,phone,password_hash,role) VALUES(?,?,?,?, 'citizen')",
                                (name, email, phone, generate_password_hash(password)))
            user = user_by_id(db, cursor.lastrowid)
        return jsonify({"ok": True, "message": "Citizen account created. Please sign in.", "user": dict(user)}), 201
    except sqlite3.IntegrityError:
        return fail("An account with this email already exists.", 409)


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    role = str(data.get("role", "citizen")).strip().lower()
    if role not in ROLE_NAMES:
        return fail("Choose Citizen, Municipal Authority or Repair Worker.")
    with connect() as db:
        row = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not row:
            return fail("Email, password or selected role is incorrect.", 401)
        if row["locked_until"] and db.execute("SELECT ? > datetime('now')", (row["locked_until"],)).fetchone()[0]:
            return fail(f"Too many failed attempts. Try again after {config.LOCKOUT_MINUTES} minutes or reset your password.", 429)
        if not check_password_hash(row["password_hash"], password):
            failed = (row["failed_logins"] or 0) + 1
            if failed >= config.MAX_FAILED_LOGINS:
                db.execute("UPDATE users SET failed_logins=0, locked_until=datetime('now', ?) WHERE id=?", (f"+{config.LOCKOUT_MINUTES} minutes", row["id"]))
                return fail(f"Too many failed attempts. Your account is locked for {config.LOCKOUT_MINUTES} minutes.", 429)
            db.execute("UPDATE users SET failed_logins=? WHERE id=?", (failed, row["id"]))
            return fail(f"Email, password or selected role is incorrect. {config.MAX_FAILED_LOGINS - failed} attempt(s) left.", 401)
        if row["role"] != role:
            return fail(f"This is not a {ROLE_NAMES[role]} account. Use 'Change role' to choose the correct role.", 403)
        db.execute("UPDATE users SET failed_logins=0, locked_until=NULL WHERE id=?", (row["id"],))
        token = create_session(db, row["id"])
        user = {k: row[k] for k in ("id", "name", "email", "phone", "role")}
    return jsonify({"ok": True, "token": token, "expires_in_days": config.SESSION_DAYS, "user": user})


@app.post("/api/logout")
@require_auth()
def logout():
    token = request.headers.get("Authorization", "")[7:].strip()
    with connect() as db:
        db.execute("UPDATE sessions SET revoked=1 WHERE token_hash=?", (hash_token(token),))
    return jsonify({"ok": True, "message": "Signed out."})


@app.get("/api/me")
@require_auth()
def me():
    user = dict(g.user)
    user.pop("session_id", None)
    out = {"ok": True, "user": user}
    with connect() as db:
        if user["role"] == "citizen":
            out["contribution"] = citizen_score(db, user["id"])
        elif user["role"] == "worker":
            out["stats"] = dict(db.execute(f"""SELECT COUNT(*) AS assigned,
                SUM(CASE WHEN status NOT IN {OPEN_STATUSES_SQL} AND status!='Pending Verification' THEN 1 ELSE 0 END) AS open_jobs,
                SUM(CASE WHEN status='Completed' THEN 1 ELSE 0 END) AS completed
                FROM complaints WHERE assigned_worker_id=?""", (user["id"],)).fetchone())
        else:
            out["stats"] = dict(db.execute(f"""SELECT COUNT(*) AS total,
                SUM(CASE WHEN status NOT IN {OPEN_STATUSES_SQL} THEN 1 ELSE 0 END) AS open_complaints,
                SUM(CASE WHEN high_emergency=1 AND status NOT IN {OPEN_STATUSES_SQL} THEN 1 ELSE 0 END) AS emergencies,
                SUM(CASE WHEN status='Pending Verification' THEN 1 ELSE 0 END) AS awaiting_verification,
                SUM(CASE WHEN ai_review=1 AND status NOT IN {OPEN_STATUSES_SQL} THEN 1 ELSE 0 END) AS needs_photo_review
                FROM complaints""").fetchone())
    return jsonify(out)


@app.post("/api/password/forgot")
def forgot_password():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    generic = {"ok": True, "message": f"If an account exists for this email, a 6-digit reset code has been sent. It is valid for {config.RESET_CODE_MINUTES} minutes."}
    if "@" not in email:
        return fail("Enter a valid email address.")
    with connect() as db:
        user = db.execute("SELECT id, name, email FROM users WHERE email=?", (email,)).fetchone()
        if not user:
            return jsonify(generic)
        recent = db.execute("SELECT COUNT(*) FROM password_resets WHERE user_id=? AND created_at > datetime('now', ?)",
                            (user["id"], f"-{config.RESET_CODE_MINUTES} minutes")).fetchone()[0]
        if recent >= config.RESET_MAX_REQUESTS_PER_WINDOW:
            return fail("Too many reset requests. Please wait a few minutes and try again.", 429)
        code = f"{secrets.randbelow(1_000_000):06d}"
        db.execute("UPDATE password_resets SET used=1 WHERE user_id=? AND used=0", (user["id"],))
        db.execute("INSERT INTO password_resets(user_id, code_hash, expires_at) VALUES(?,?,datetime('now', ?))",
                   (user["id"], generate_password_hash(code), f"+{config.RESET_CODE_MINUTES} minutes"))
    if not smtp_configured():
        print(f"[GarudaX] Email not configured - password reset code for {email}: {code}")
    send_email(email, "GarudaX password reset code",
               f"Hello {user['name']},\n\nYour GarudaX password reset code is: {code}\n\nIt is valid for {config.RESET_CODE_MINUTES} minutes. "
               "If you did not request this, you can ignore this email.\n\n— GarudaX")
    return jsonify(generic)


@app.post("/api/password/reset")
def reset_password():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    code = str(data.get("code", "")).strip()
    new_password = str(data.get("new_password", ""))
    problem = password_problem(new_password)
    if problem:
        return fail(problem)
    with connect() as db:
        user = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        reset = db.execute("""SELECT * FROM password_resets WHERE user_id=? AND used=0 AND expires_at > datetime('now')
                              ORDER BY id DESC LIMIT 1""", (user["id"] if user else -1,)).fetchone()
        if not user or not reset:
            return fail("The reset code is invalid or has expired. Request a new code.", 400)
        if reset["attempts"] >= config.RESET_MAX_ATTEMPTS:
            db.execute("UPDATE password_resets SET used=1 WHERE id=?", (reset["id"],))
            return fail("Too many wrong codes. Request a new code.", 429)
        if not check_password_hash(reset["code_hash"], code):
            db.execute("UPDATE password_resets SET attempts=attempts+1 WHERE id=?", (reset["id"],))
            return fail("The reset code is incorrect.", 400)
        db.execute("UPDATE password_resets SET used=1 WHERE id=?", (reset["id"],))
        db.execute("UPDATE users SET password_hash=?, failed_logins=0, locked_until=NULL WHERE id=?", (generate_password_hash(new_password), user["id"]))
        revoke_all_sessions(db, user["id"])
    return jsonify({"ok": True, "message": "Password changed. Please sign in with your new password."})


# ------------------------------------------------------------------ complaints
@app.post("/api/complaints")
@require_auth("citizen")
def create_complaint():
    citizen = g.user
    try:
        latitude = float(request.form.get("latitude", "nan"))
        longitude = float(request.form.get("longitude", "nan"))
    except ValueError:
        return fail("Live GPS coordinates are required.")
    description = request.form.get("description", "").strip()
    urgent = str(request.form.get("urgent", "0")).lower() in ("1", "true", "yes")
    if not description:
        return fail("Add a short description of the road damage.")
    if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
        return fail("Valid live GPS coordinates are required.")
    if request.form.get("capture_source", "camera") != "camera":
        return fail("Only photos taken with the camera are accepted.")
    payload, extension, error = read_photo()
    if error:
        return error
    if photo_too_old(payload):
        return fail(f"This photo was taken more than {config.MAX_PHOTO_AGE_HOURS} hours ago. Take a new photo at the location.", 422)
    sha, dh = sha256_hex(payload), dhash_hex(payload)
    with connect() as db:
        repeated = find_repeated_photo(db, sha, dh)
    if repeated:
        cid, kind = repeated
        word = "has already been used" if kind == "exact" else "is almost identical to a photo already used"
        return fail(f"This photo {word} in complaint #GX-{cid:05d}. Please take a new photo of the damage.", 409, repeated_photo=True, existing_complaint_id=cid)

    temp_path = config.UPLOADS / ("check_" + uuid.uuid4().hex + extension)
    temp_path.write_bytes(payload)
    floor = config.AI_REVIEW_MIN_CONFIDENCE if config.AI_REVIEW_ENABLED else config.MIN_AI_CONFIDENCE
    try:
        detection = detect_damage(temp_path, min(floor, config.MIN_AI_CONFIDENCE))
    finally:
        remove_quietly(temp_path)
    if not detection.get("available"):
        return fail("AI validation is unavailable. The complaint was not saved. Please try again later.", 503, detection=detection)
    try:
        confidence_value = float(detection.get("confidence"))
    except (TypeError, ValueError):
        confidence_value = 0.0
    if confidence_value <= 0.0:
        return fail("AI detected no road damage (confidence 0). The complaint was rejected and not saved.", 422, rejected=True, detection=detection)
    needs_review = False
    if confidence_value < config.MIN_AI_CONFIDENCE:
        if not config.AI_REVIEW_ENABLED:
            return fail(f"AI confidence {confidence_value:.0%} is below the required {config.MIN_AI_CONFIDENCE:.0%}. "
                        "Take a clearer, closer photo of the damage.", 422, rejected=True, detection=detection)
        if confidence_value < config.AI_REVIEW_MIN_CONFIDENCE:
            return fail(f"AI found no clear road damage in this photo ({confidence_value:.0%} confidence). "
                        "Take a clearer, closer photo of the damage in daylight.", 422, rejected=True, detection=detection)
        needs_review = True   # AI unsure: keep the complaint but ask the authority to check the photo
    label = detection.get("label", "")

    with connect() as db:
        dup = find_duplicate_location(db, latitude, longitude, label)
        if dup:
            existing, dist = dup
            if existing["citizen_id"] == citizen["id"]:
                return fail(f"You have already reported this damage (complaint #GX-{existing['id']:05d}, {dist:.0f} m away).", 409,
                            duplicate=True, existing_complaint_id=existing["id"])
            added = db.execute("INSERT OR IGNORE INTO complaint_supporters(complaint_id, citizen_id) VALUES(?,?)", (existing["id"], citizen["id"])).rowcount
            if added:
                db.execute("UPDATE complaints SET support_count=support_count+1, updated_at=CURRENT_TIMESTAMP WHERE id=?", (existing["id"],))
                add_history(db, existing["id"], citizen["id"], "Also Reported", f"Same {label} reported again by another citizen ({dist:.0f} m away); priority increased")
            return fail(f"This {label} is already reported as complaint #GX-{existing['id']:05d} ({dist:.0f} m away). "
                        "Your report was added as a confirmation and its priority was increased (+2 points).", 409,
                        duplicate=True, confirmed=bool(added), existing_complaint_id=existing["id"])
        filename = save_photo(payload, extension)
        cursor = db.execute("""INSERT INTO complaints
            (citizen_id,description,latitude,longitude,address,photo_filename,damage_type,confidence,ai_available,status,citizen_urgent,photo_sha256,photo_dhash,ai_review)
            VALUES(?,?,?,?,?,?,?,?,1,'Pending',?,?,?,?)""",
            (citizen["id"], description, latitude, longitude, request.form.get("address", "").strip(), filename, label,
             round(confidence_value * 100, 1), 1 if urgent else 0, sha, dh, 1 if needs_review else 0))
        complaint_id = cursor.lastrowid
        ai_note = (f"AI unsure ({label}, {confidence_value:.0%}); sent to municipal authority for manual photo review" if needs_review
                   else f"AI detected {label} ({confidence_value:.0%})")
        add_history(db, complaint_id, citizen["id"], "Pending",
                    f"Complaint submitted with camera photo; {ai_note}" + ("; marked urgent by citizen" if urgent else ""))
        c = load_complaint(db, complaint_id)
    email_status = email_complaint_pdf(complaint_id, citizen["email"], f"GarudaX complaint #GX-{complaint_id:05d} registered",
                                       f"Hello {citizen['name']},\n\nThank you! Your road damage complaint has been verified by AI and registered.")
    message = (f"The AI was not sure this photo shows road damage ({confidence_value:.0%} confidence), so your complaint was sent to the "
               "Municipal Authority to check the photo. You get +10 points when they approve it." if needs_review
               else "Complaint submitted. +10 contribution points.")
    return jsonify({"ok": True, "message": message, "needs_review": needs_review, "complaint_id": complaint_id,
                    "detection": detection, "complaint": c, "email_status": email_status}), 201


@app.get("/api/complaints")
@require_auth()
def list_complaints():
    user = g.user
    run_escalation()
    with connect() as db:
        if user["role"] == "citizen":
            rows = db.execute(COMPLAINT_SELECT + " WHERE c.citizen_id=? ORDER BY c.id DESC", (user["id"],)).fetchall()
        elif user["role"] == "worker":
            rows = db.execute(COMPLAINT_SELECT + " WHERE c.assigned_worker_id=?", (user["id"],)).fetchall()
        else:
            rows = db.execute(COMPLAINT_SELECT).fetchall()
    complaints = [complaint_dict(r) for r in rows]
    if user["role"] != "citizen":   # emergency prioritisation: open emergencies first, then by priority score
        complaints.sort(key=lambda c: (c["status"] in ("Completed", "Rejected"), -c["high_emergency"], -c["priority_score"], -c["id"]))
    return jsonify({"ok": True, "complaints": complaints})


@app.get("/api/complaints/<int:complaint_id>")
@require_auth()
def complaint_detail(complaint_id):
    with connect() as db:
        c = load_complaint(db, complaint_id)
        if not c:
            return fail("Complaint not found.", 404)
        if not can_view(g.user, c):
            return fail("You do not have access to this complaint.", 403)
        history = load_history(db, complaint_id)
    return jsonify({"ok": True, "complaint": c, "history": history})


@app.get("/api/workers")
@require_auth("authority")
def list_workers():
    with connect() as db:
        workers = db.execute(f"""SELECT u.id,u.name,u.email,u.phone,
            (SELECT COUNT(*) FROM complaints c WHERE c.assigned_worker_id=u.id AND c.status NOT IN {OPEN_STATUSES_SQL}) AS open_jobs
            FROM users u WHERE u.role='worker' ORDER BY u.name""").fetchall()
    return jsonify({"ok": True, "workers": [dict(w) for w in workers]})


AUTHORITY_TRANSITIONS = {
    "Under Review": {"Pending"},
    "Assigned": {"Pending", "Under Review", "Assigned"},
    "Rejected": {"Pending", "Under Review", "Assigned"},
    "Completed": {"Pending Verification"},
    "Rework Required": {"Pending Verification"},
}


@app.put("/api/complaints/<int:complaint_id>/status")
@require_auth("authority")
def update_authority_status(complaint_id):
    actor = g.user
    data = request.get_json(silent=True) or {}
    status = str(data.get("status", "")).strip()
    note = str(data.get("note", "")).strip()
    with connect() as db:
        row = db.execute("SELECT * FROM complaints WHERE id=?", (complaint_id,)).fetchone()
        if not row:
            return fail("Complaint not found.", 404)
        if status not in AUTHORITY_TRANSITIONS:
            return fail("Choose Under Review, Assigned, Rejected, Completed or Rework Required.")
        if row["status"] not in AUTHORITY_TRANSITIONS[status]:
            hints = {"Completed": "A repair can be completed only after the worker submits it with an after-repair photo.",
                     "Rework Required": "Rework can be requested only for a repair pending verification."}
            return fail(hints.get(status, f"Cannot change a complaint from '{row['status']}' to '{status}'."), 409)
        worker_id = row["assigned_worker_id"]
        if status == "Assigned":
            try:
                worker_id = int(data.get("worker_id") or 0)
            except (TypeError, ValueError):
                worker_id = 0
            worker = user_by_id(db, worker_id) if worker_id else None
            if not worker or worker["role"] != "worker":
                return fail("Select a repair worker before assigning the complaint.")
        if status == "Completed" and not row["after_photo_filename"]:
            return fail("The worker has not uploaded an after-repair photo yet.", 409)
        if status in ("Rejected", "Rework Required") and not note:
            note = "Rejected by municipal authority" if status == "Rejected" else "Repair not acceptable; rework required"
        note = note or {"Under Review": "Complaint under review by municipal authority",
                        "Assigned": "Assigned to repair worker", "Completed": "Repair verified and completed by municipal authority"}[status]
        if row["ai_review"] and status in ("Under Review", "Assigned"):
            db.execute("UPDATE complaints SET ai_review=0 WHERE id=?", (complaint_id,))
            add_history(db, complaint_id, actor["id"], "Photo Approved", "Photo checked manually and approved by municipal authority")
        db.execute("""UPDATE complaints SET status=?, assigned_worker_id=?, updated_at=CURRENT_TIMESTAMP,
                      verification_note=CASE WHEN ? IN ('Completed','Rework Required','Rejected') THEN ? ELSE verification_note END,
                      completed_at=CASE WHEN ?='Completed' THEN CURRENT_TIMESTAMP ELSE completed_at END WHERE id=?""",
                   (status, worker_id, status, note, status, complaint_id))
        add_history(db, complaint_id, actor["id"], status, note)
        c = load_complaint(db, complaint_id, public=False)
    email_status = None
    if status == "Completed":
        email_status = email_complaint_pdf(complaint_id, c["citizen_email"], f"GarudaX complaint #GX-{complaint_id:05d} repaired",
                                           f"Hello {c['citizen_name']},\n\nGood news! The road damage you reported has been repaired and verified. You earned +15 contribution points.")
    elif status == "Assigned" and c.get("worker_email"):
        email_status = send_email(c["worker_email"], f"New repair job #GX-{complaint_id:05d}",
                                  f"Hello {c['worker_name']},\n\nA new repair job has been assigned to you.\nDamage: {c['damage_type']}\n"
                                  f"Location: https://maps.google.com/?q={c['latitude']},{c['longitude']}\nPriority: {c['priority_label']}\n\n"
                                  "Open the GarudaX app, take a BEFORE photo and start the repair.\n\n— GarudaX")
    elif status == "Rejected":
        email_status = send_email(c["citizen_email"], f"GarudaX complaint #GX-{complaint_id:05d} rejected",
                                  f"Hello {c['citizen_name']},\n\nYour complaint was rejected by the municipal authority.\nReason: {note}\n\n— GarudaX")
    return jsonify({"ok": True, "message": "Complaint updated.", "status": status, "email_status": email_status})


@app.post("/api/complaints/<int:complaint_id>/worker-status")
@require_auth("worker")
def update_worker_status(complaint_id):
    worker = g.user
    status = request.form.get("status", "").strip()
    note = request.form.get("note", "").strip()
    with connect() as db:
        row = db.execute("SELECT * FROM complaints WHERE id=?", (complaint_id,)).fetchone()
    if not row:
        return fail("Complaint not found.", 404)
    if row["assigned_worker_id"] != worker["id"]:
        return fail("This repair is not assigned to your account.", 403)
    if status not in ("Repair In Progress", "Repair Completed"):
        return fail("Worker status must be Repair In Progress or Repair Completed.")
    if row["status"] in ("Completed", "Rejected"):
        return fail("This complaint is already closed and cannot be changed by a worker.", 409)
    if status == "Repair In Progress" and row["status"] not in ("Assigned", "Rework Required"):
        return fail("The complaint must be assigned to you before repair can start.", 409)
    if status == "Repair Completed" and row["status"] != "Repair In Progress":
        return fail("Start the repair (with a before photo) before submitting it.", 409)

    photo_required = status == "Repair Completed" or not row["before_photo_filename"]
    payload = None
    has_photo = bool(request.files.get("photo") and request.files["photo"].filename)
    if photo_required and not has_photo:
        which = "a BEFORE" if status == "Repair In Progress" else "an AFTER"
        return fail(f"Take {which}-repair photo with the camera.")
    if has_photo:
        payload, extension, error = read_photo()
        if error:
            return error
        if photo_too_old(payload):
            return fail(f"This photo is older than {config.MAX_PHOTO_AGE_HOURS} hours. Take a new photo at the site.", 422)
        sha, dh = sha256_hex(payload), dhash_hex(payload)
        with connect() as db:
            repeated = find_repeated_photo(db, sha, dh, exclude_id=complaint_id)
        if repeated:
            return fail(f"This photo was already used in complaint #GX-{repeated[0]:05d}. Take a new photo.", 409, repeated_photo=True)
        if row["photo_sha256"] == sha or row["before_photo_sha256"] == sha:
            return fail("This is the same photo that is already attached to this complaint. Take a new photo.", 409, repeated_photo=True)
        if status == "Repair Completed":
            for previous in (row["before_photo_dhash"], row["photo_dhash"]):
                if previous and hamming(previous, dh) <= 2:
                    return fail("The after-repair photo looks identical to the photo taken before repair. Take a photo of the repaired road.", 409, repeated_photo=True)
    with connect() as db:
        if status == "Repair In Progress":
            stored = "Repair In Progress"
            if payload is not None:
                db.execute("UPDATE complaints SET before_photo_filename=?, before_photo_sha256=?, before_photo_dhash=? WHERE id=?",
                           (save_photo(payload, extension), sha, dh, complaint_id))
            note = note or ("Worker restarted repair (rework)" if row["status"] == "Rework Required" else "Worker started repair; before-repair photo uploaded")
        else:
            stored = "Pending Verification"
            db.execute("UPDATE complaints SET after_photo_filename=?, after_photo_sha256=?, after_photo_dhash=? WHERE id=?",
                       (save_photo(payload, extension), sha, dh, complaint_id))
            note = note or "Worker submitted repair with after-repair photo for municipal verification"
        db.execute("UPDATE complaints SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", (stored, complaint_id))
        add_history(db, complaint_id, worker["id"], stored, note)
        c = load_complaint(db, complaint_id)
    return jsonify({"ok": True, "message": "Repair status updated.", "status": stored, "complaint": c})


@app.get("/api/complaints/<int:complaint_id>/report.pdf")
@require_auth()
def complaint_pdf(complaint_id):
    with connect() as db:
        c = load_complaint(db, complaint_id, public=False)
        if not c:
            return fail("Complaint not found.", 404)
        if not can_view(g.user, c):
            return fail("You do not have access to this complaint.", 403)
        history = load_history(db, complaint_id)
    pdf = build_complaint_pdf(c, history)
    return send_file(BytesIO(pdf), mimetype="application/pdf", as_attachment=True, download_name=f"GarudaX_Complaint_GX-{complaint_id:05d}.pdf")


@app.post("/api/complaints/<int:complaint_id>/email-report")
@require_auth()
def email_report(complaint_id):
    with connect() as db:
        c = load_complaint(db, complaint_id)
    if not c:
        return fail("Complaint not found.", 404)
    if not can_view(g.user, c):
        return fail("You do not have access to this complaint.", 403)
    status = email_complaint_pdf(complaint_id, g.user["email"], f"GarudaX report for complaint #GX-{complaint_id:05d}",
                                 f"Hello {g.user['name']},\n\nAs requested, here is the GarudaX report for this complaint.")
    msg = (f"PDF report is being emailed to {g.user['email']}." if status == "sending"
           else "Email is not configured on the server, so the PDF email was saved in the server's outbox folder.")
    return jsonify({"ok": True, "message": msg, "email_status": status})


@app.get("/uploads/<path:filename>")
def uploaded_photo(filename):
    return send_from_directory(str(config.UPLOADS), Path(filename).name)


@app.errorhandler(Exception)
def unexpected_error(error):
    """Any unexpected server error: log the full details and send a readable message to the app
    (instead of a bare "HTTP 500")."""
    from werkzeug.exceptions import HTTPException
    if isinstance(error, HTTPException):
        return fail(error.description or error.name, error.code or 500)
    import traceback
    details = traceback.format_exc()
    log_dir = Path(__file__).resolve().parent / "logs"
    try:
        log_dir.mkdir(exist_ok=True)
        with open(log_dir / "errors.log", "a", encoding="utf-8") as fh:
            fh.write(f"\n===== {datetime.now():%Y-%m-%d %H:%M:%S}  {request.method} {request.path}\n{details}")
    except OSError:
        pass
    print(f"[GarudaX] SERVER ERROR on {request.method} {request.path}:\n{details}")
    reason = f"{type(error).__name__}: {error}"
    hint = ""
    text = str(error).lower()
    if "database is locked" in text:
        hint = " Close DB Browser / any program that has garudax_data.db open, then try again."
    elif "no such column" in text or "no such table" in text:
        hint = " Restart the backend (python app.py) so it can upgrade the database."
    elif "permission" in text or "winerror" in text:
        hint = " Windows blocked a file. Run the backend from a normal folder (not OneDrive/Desktop sync) and try again."
    return fail(f"Server error: {reason[:200]}.{hint} Details are in backend/logs/errors.log", 500)


@app.errorhandler(413)
def too_large(_error):
    return fail("Photo is too large. Maximum upload size is 12 MB.", 413)


def lan_addresses():
    """IPv4 addresses of this laptop that a phone on the same Wi-Fi can use."""
    import socket
    found = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # no data is sent; this only picks the active network card
        found.append(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127.") and ip not in found:
                found.append(ip)
    except OSError:
        pass
    return found


if __name__ == "__main__":
    start_scheduler()
    ips = lan_addresses()
    print("=" * 64)
    if ips:
        for ip in ips:
            print(f"  Phone server address:  {ip}:5000")
        print("  In the app tap 'Server' on the sign-in screen and type this address.")
    else:
        print("  No Wi-Fi network found. Connect the laptop to Wi-Fi / hotspot first.")
    print("  Phone and laptop must be on the same Wi-Fi (phone mobile data OFF).")
    print("=" * 64)
    print("GarudaX API running. Email mode:", "SMTP" if smtp_configured() else "outbox (configure backend/.env to send real emails)")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
