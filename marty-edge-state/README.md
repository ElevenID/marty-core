# Marty edge state

Small, synchronous state transitions for an offline verifier. This crate does not
verify credentials, authenticate trust updates, provision policy, or contact a
network service. A caller supplies an already-authenticated trust revision and
a SHA-256-sized, context-bound replay key. The replay window fails closed at
capacity; it never evicts a live entry to admit another request.

Persist `snapshot_json()` atomically before reporting a verification as accepted.
Commit a new revision with its matching trust/policy package so the revision
cannot advance independently of the package. The host must protect the snapshot
against tampering and maintain independently protected monotonic floors for
generation, revision, and clock values across restarts. Pass all three floors
to `restore()`. The generation floor must advance for **every** accepted replay
key, including multiple acceptances in the same second, or an earlier snapshot
can erase an accepted key. The host must persist the snapshot and advance its
protected floor before acknowledging acceptance; a crash that advances the
floor without the matching snapshot must fail closed on restart. A replaced old
snapshot cannot be detected from the snapshot alone. The host must also provide
a trustworthy clock, authenticate trust and policy packages, derive replay keys
from the authenticated context, and handle audit durability. This is a
foundation, **not** a qualified headless verifier, installer, or offline
security claim.
