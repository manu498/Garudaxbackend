"""Email delivery. Uses SMTP when configured in .env; otherwise (or if sending fails) the email,
with its PDF attachment, is saved as an .eml file in backend/outbox so nothing is lost."""
import smtplib
import ssl
import threading
import uuid
from datetime import datetime
from email.message import EmailMessage

import config
from database import connect


def smtp_configured() -> bool:
    return bool(config.SMTP_HOST)


def _build(to_address, subject, body, attachments):
    msg = EmailMessage()
    msg["From"] = f"GarudaX <{config.SMTP_FROM}>"
    msg["To"] = to_address
    msg["Subject"] = subject
    msg.set_content(body)
    for filename, data, mime in attachments or []:
        maintype, subtype = mime.split("/", 1)
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    return msg


def _log(to_address, subject, status, detail=""):
    try:
        with connect() as db:
            db.execute("INSERT INTO email_log(to_address,subject,status,detail) VALUES(?,?,?,?)",
                       (to_address, subject, status, detail[:500]))
    except Exception:
        pass


def _save_to_outbox(msg, reason):
    config.OUTBOX.mkdir(exist_ok=True)
    path = config.OUTBOX / f"{datetime.now():%Y%m%d_%H%M%S}_{uuid.uuid4().hex[:6]}.eml"
    path.write_bytes(bytes(msg))
    print(f"[GarudaX mail] {reason}. Saved email for {msg['To']} to {path}")
    return path


def _send_now(msg):
    to_address, subject = msg["To"], msg["Subject"]
    if not smtp_configured():
        path = _save_to_outbox(msg, "SMTP not configured")
        _log(to_address, subject, "saved_to_outbox", path.name)
        return "saved_to_outbox"
    try:
        context = ssl.create_default_context()
        if config.SMTP_USE_SSL:
            server = smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT, context=context, timeout=30)
        else:
            server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=30)
            server.starttls(context=context)
        with server:
            if config.SMTP_USER:
                server.login(config.SMTP_USER, config.SMTP_PASSWORD)
            server.send_message(msg)
        _log(to_address, subject, "sent")
        print(f"[GarudaX mail] Sent '{subject}' to {to_address}")
        return "sent"
    except Exception as exc:  # network / login problems must never crash the API
        path = _save_to_outbox(msg, f"SMTP send failed ({exc.__class__.__name__}: {exc})")
        _log(to_address, subject, "failed_saved_to_outbox", f"{exc} -> {path.name}")
        return "failed_saved_to_outbox"


def send_email(to_address, subject, body, attachments=None, background=True):
    """Send (or save) an email. Returns 'sending' / 'sent' / 'saved_to_outbox' / 'failed_saved_to_outbox'."""
    if not to_address:
        return "no_recipient"
    msg = _build(to_address, subject, body, attachments)
    if background:
        threading.Thread(target=_send_now, args=(msg,), daemon=True).start()
        return "sending" if smtp_configured() else "saved_to_outbox"
    return _send_now(msg)
