---
"@stripe/link-cli": patch
---

Harden SDK error handling: malformed or unexpected API responses now surface a clearer `invalid_response` error instead of an opaque parse failure.
