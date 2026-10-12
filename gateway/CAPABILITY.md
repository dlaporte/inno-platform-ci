# Gateway capability number

`capability.json` holds one integer that only ever goes up. Tenant CI reads it
from the gateway source it checked out at `gateway.ref` and reports it at
deploy-complete, and the platform stores it per deployment. `gateway.ref` is an
unordered commit SHA, so this number is how the platform tells whether a
deployed gateway can do something newer.

- 0: no membership enforcement (every gateway before this file existed reads as 0).
- 1: the gateway checks membership through `/_access/check`.

A missing file or field reads as 0, never a refusal: CI's `ci/` runs at `main`
against gateway source that may be older.
