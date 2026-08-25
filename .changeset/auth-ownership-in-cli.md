---
"@stripe/link-cli": patch
---

Move OAuth device-authorization, refresh-token persistence, and login state ownership from the SDK into the CLI; the SDK now only accepts credentials. No change to CLI commands or output.
