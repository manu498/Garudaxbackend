"""Create the local database and demo staff accounts."""
from werkzeug.security import generate_password_hash
from database import connect, init_db

init_db()
DEMO_USERS = [
    ("Municipal Demo", "authority@garudax.local", "", "Authority@123", "authority"),
    ("Repair Worker Demo", "worker@garudax.local", "", "Worker@123", "worker"),
]
with connect() as db:
    for name, email, phone, password, role in DEMO_USERS:
        exists = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if not exists:
            db.execute("INSERT INTO users(name,email,phone,password_hash,role) VALUES(?,?,?,?,?)",
                       (name, email, phone, generate_password_hash(password), role))
print("GarudaX SQLite database is ready.")
print("Demo Municipal Authority: authority@garudax.local / Authority@123")
print("Demo Repair Worker:      worker@garudax.local / Worker@123")
print("Citizen accounts are created from the Android app.")
