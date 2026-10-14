# Gateway capability number

`capability.json` holds one integer that only ever goes up. Tenant CI reads it
from the gateway source it checked out at `gateway.ref` and sends it twice: to
`/deploy-token`, which refuses every browser app, whatever its record, when
the number is below 1 (`gateway_too_old`), and to `/deploy-complete`, which
stores it with the deployment. `gateway.ref` is an unordered commit SHA, so
this number is how the platform tells whether a deployed gateway can do
something newer.

- 0: no membership enforcement (every gateway before this file existed reads as 0).
  Cloudflare Access alone decides who reaches a browser app.
- 1: the gateway asks `/_access/check` about every person on a browser app.
  After Access verifies who the person is, the gateway POSTs `{host, jwt}` to
  the platform over the `PLATFORM` binding, presenting
  `GATEWAY_INTROSPECT_KEY` when it holds one, and:
  - on an allow, forwards the request, with `X-Forwarded-Groups` taken from
    the answer's `groups` (never the JWT's groups claim);
  - on a refusal, answers a plain 403 page that names no one;
  - when the platform cannot be reached, answers anything but 200, or
    answers a body that is not a decision, answers a 503 page (it fails
    closed).

  Each answer is held per isolate, by host and email, for the `ttl` it
  carries (at most 60 seconds); an unanswered check is never held. The
  health probe's service token, which carries no person, is not checked.
  The MCP path is unchanged.

A gateway built from v0.16.10 on also answers its 503 page while it cannot
obtain Access's signing keys (except to `GET /healthz`, which keeps its 401),
where an earlier capability-1 gateway answers 401. The platform reads nothing
from that difference, so the number stays 1: a change the platform need not
know about never raises it.

A missing file or field reads as 0, never a refusal of its own: CI's `ci/`
runs at `main` against gateway source that may be older.
