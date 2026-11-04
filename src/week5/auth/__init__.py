"""Username + password sign-in for the CyberSight console: password hashing, server-side sessions, CSRF, throttling, one-time bootstrap and account administration.
Layout: passwords (hashing and policy) - settings (WEEK5_* variables) - store (PostgreSQL functions of migration 0003) - service (the rules) - web (cookie, origin, CSRF)
- routes_auth + api_auth (the HTTP routes, as a mixin of Api5). Design and operation: docs/AUTHENTICATION.md."""
