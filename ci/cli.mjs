// Shared "am I the script node was told to run?" guard for every ci/ and
// scripts/ CLI's main block. Lives on its own (not in broker-post.mjs, its
// former home) so scripts/ — which has no reason to depend on the broker
// helper — can import it standalone.
//
// Fixed here: the old broker-post.mjs version compared
// `importMetaUrl === \`file://${process.argv[1]}\`` — a hand-built template
// that breaks for any argv[1] path needing percent-encoding (spaces, etc.):
// file URLs percent-encode such characters, so the template never matches
// and the CLI block silently no-ops. pathToFileURL(...).href performs the
// same encoding Node's own import.meta.url uses, so comparing against that
// is exact.
import { pathToFileURL } from "node:url";

/**
 * True when the module whose `import.meta.url` is passed is the entry point node
 * was invoked with (i.e. run directly, not imported). Callers pass their OWN
 * `import.meta.url` because it is lexically bound to the calling module.
 *
 * @param {string} importMetaUrl - the caller's import.meta.url
 * @returns {boolean}
 */
export function isMainModule(importMetaUrl) {
  if (!process.argv[1]) return false;
  return importMetaUrl === pathToFileURL(process.argv[1]).href;
}
