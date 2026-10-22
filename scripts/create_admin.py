"""Create the first administrator interactively. The password is never echoed, logged or stored in plaintext."""
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app import create_app  # noqa: E402
from app.db import connect  # noqa: E402
from app.security import validate_password  # noqa: E402
from app.services import create_user  # noqa: E402

app = create_app()
username = input("Admin username: ").strip().lower()
email = input("Admin email: ").strip().lower()
pw = getpass.getpass("Password (12+ chars): ")
if pw != getpass.getpass("Repeat password: "):
    sys.exit("Passwords do not match.")
with app.app_context():
    errs = validate_password(pw, username)
    if errs:
        sys.exit("\n".join(errs))
    db = connect(app.config["DATABASE"])
    create_user(db, username, email, pw, "admin")
    print(f"Administrator '{username}' created in {app.config['DATABASE']}")
