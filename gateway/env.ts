import type { AppContainer } from "./index";

export type Env = {
  DB: D1Database; FILES: R2Bucket; APP: DurableObjectNamespace<AppContainer>;
  ACCESS_AUD: string; ACCESS_TEAM_DOMAIN: string; ENVIRONMENT: string;
  // Injected at deploy time by platform-ci (config store: container.sleep_after).
  SLEEP_AFTER?: string;
  // Present ONLY on worker-type apps: a service binding to the app's own Worker
  // (the "Worker behind the same gateway" deployment type). When set, the
  // gateway forwards authenticated requests here instead of to the container —
  // the app Worker is not publicly routable, so the gateway stays the only
  // entrypoint and identity boundary. Container-type apps never bind this.
  APP_WORKER?: Fetcher;
};
