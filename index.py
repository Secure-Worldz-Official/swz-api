# Vercel serverless entry point
# This file is the adapter that Vercel uses to serve the Flask app.
# It does NOT modify any logic in main.py or libs.py.

import sys
import os

# Ensure this directory is on the path so `from libs import ...` resolves
sys.path.insert(0, os.path.dirname(__file__))

from main import app  # noqa: F401 — Vercel picks up the `app` WSGI callable
