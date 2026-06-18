# Scan Oasis — Firebase Configuration
# Edit this file to point at your own Firebase project.
# Alternatively, set environment variables with the same names.

import os

FIREBASE_API_KEY        = os.environ.get("FIREBASE_API_KEY",        "AIzaSyBr8FSPpcVtuinCm-iWKicEl_CP3JTP80o")
FIREBASE_AUTH_DOMAIN    = os.environ.get("FIREBASE_AUTH_DOMAIN",    "oasis-scanner-c988d.firebaseapp.com")
FIREBASE_PROJECT        = os.environ.get("FIREBASE_PROJECT",        "oasis-scanner-c988d")
FIREBASE_STORAGE_BUCKET = os.environ.get("FIREBASE_STORAGE_BUCKET", "oasis-scanner-c988d.firebasestorage.app")
FIREBASE_MESSAGING_ID   = os.environ.get("FIREBASE_MESSAGING_ID",   "661728874468")
FIREBASE_APP_ID         = os.environ.get("FIREBASE_APP_ID",         "1:661728874468:web:961e64b143b60f6dc881f1")
