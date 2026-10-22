"""WSGI entry point: `waitress-serve --listen=127.0.0.1:8000 wsgi:app` (Windows) or gunicorn (Linux)."""
from app import create_app

app = create_app()
