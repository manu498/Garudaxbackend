"""Add an authorised Municipal Authority or Repair Worker account (staff cannot self-register in the app).

Usage (from the backend folder):
  .\\venv\\Scripts\\python.exe create_staff.py worker "Ramesh Patil" ramesh@pmc.gov.in Worker@2026
  .\\venv\\Scripts\\python.exe create_staff.py authority "Ward Officer" officer@pmc.gov.in Officer@2026
"""
import sys
from werkzeug.security import generate_password_hash
from database import connect, init_db
from security import password_problem

if len(sys.argv) != 5 or sys.argv[1] not in ("authority", "worker"):
    print(__doc__)
    sys.exit(1)
role, name, email, password = sys.argv[1], sys.argv[2], sys.argv[3].strip().lower(), sys.argv[4]
problem = password_problem(password)
if problem:
    print("Error:", problem)
    sys.exit(1)
init_db()
with connect() as db:
    if db.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
        print("Error: an account with this email already exists.")
        sys.exit(1)
    db.execute("INSERT INTO users(name,email,phone,password_hash,role) VALUES(?,?,?,?,?)",
               (name, email, "", generate_password_hash(password), role))
print(f"Created {role} account: {email}")
