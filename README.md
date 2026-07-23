# inno-platform-ci

The Innovation Platform's **public CI contract**: the reusable safety-gate +
deploy workflow (`.github/workflows/platform-ci.yml`), the gate scripts it
runs (`ci/`), and the gateway build inputs injected into every app deploy
(`gateway/`).

**This repo is a generated mirror — do not open PRs here.** Source of truth,
tests, and review happen in the private `inno-platform` repo; every commit
here is `publish: inno-platform@<sha>`, pushed automatically by its CI.

App repos consume this with:

    jobs:
      platform:
        uses: dlaporte/inno-platform-ci/.github/workflows/platform-ci.yml@main
        permissions: { id-token: write, contents: read }

The workflow is intentionally safe to call from untrusted repos: all
enforcement is server-side (the deploy broker verifies the signed OIDC
`job_workflow_ref` claim and refuses tokens to anything else).
