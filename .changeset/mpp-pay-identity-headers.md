---
"@stripe/link-cli": patch
---

Make `mpp pay` negotiate Link agent identity itself. It now refills the default attestation pool when needed, issues requested identity claims with the default holder key, and obtains fresh identity material before submitting the paid request.
