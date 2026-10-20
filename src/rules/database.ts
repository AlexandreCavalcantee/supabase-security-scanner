import type { Finding, RuleMeta, Severity } from "../types.js";

/** Minimal query interface so rules can run on pg.Client or pg.Pool. */
export type Queryable = { query: <R extends Record<string, unknown>>(sql: string, params?: unknown[]) => Promise<{ rows: R[] }> };

export type DbContext = {
  db: Queryable;
  /** Schemas exposed through the Data API (PostgREST). */
  schemas: string[];
};

export type DatabaseRule = RuleMeta & { run: (ctx: DbContext) => Promise<Finding[]> };

// Schemas managed by Postgres/Supabase itself; their internals are not the user's to fix.
const SYSTEM_SCHEMAS = [
  "pg_catalog",
  "information_schema",
  "pg_toast",
  "auth",
  "storage",
  "realtime",
  "_realtime",
  "extensions",
  "graphql",
  "graphql_public",
  "vault",
  "pgsodium",
  "pgsodium_masks",
  "pgbouncer",
  "net",
  "cron",
  "supabase_functions",
  "supabase_migrations",
  "_analytics",
  "tests",
];

// Who can reach the database through the API with a public or user key.
const API_ROLES = `
  case
    when has_table_privilege('anon', c.oid, 'select,insert,update,delete') and has_schema_privilege('anon', n.oid, 'usage') then 'anon'
    when has_table_privilege('authenticated', c.oid, 'select,insert,update,delete') and has_schema_privilege('authenticated', n.oid, 'usage') then 'authenticated'
  end`;

export const databaseRules: DatabaseRule[] = [
  {
    id: "SS001",
    name: "rls-disabled",
    title: "Table exposed through the API without Row Level Security",
    description:
      "Any request with the public anon key (or any logged-in user) can read and write every row the grants allow. This is the most common way Supabase apps leak data.",
    remediation: "alter table <table> enable row level security; then add policies for the access you actually want.",
    docs: "https://supabase.com/docs/guides/database/postgres/row-level-security",
    async run({ db, schemas }) {
      const { rows } = await db.query<{ schema: string; name: string; reach: string }>(
        `select n.nspname as schema, c.relname as name, ${API_ROLES} as reach
           from pg_class c join pg_namespace n on n.oid = c.relnamespace
          where c.relkind in ('r', 'p') and not c.relrowsecurity and n.nspname = any($1)`,
        [schemas],
      );
      return rows
        .filter((r) => r.reach)
        .map((r) => ({
          ruleId: "SS001",
          severity: r.reach === "anon" ? "critical" : "high",
          message: `RLS is disabled on ${r.schema}.${r.name} and the ${r.reach} role has access to it.`,
          object: { kind: "table", schema: r.schema, name: r.name },
        }));
    },
  },
  {
    id: "SS002",
    name: "rls-without-policies",
    title: "RLS enabled but no policies",
    description:
      "The table denies everything to API users. That's safe, but usually means a policy was forgotten, and the typical 'fix' under pressure is disabling RLS.",
    remediation: "Add the policies the app needs, or revoke the API grants if the table is internal only.",
    async run({ db, schemas }) {
      const { rows } = await db.query<{ schema: string; name: string; reach: string }>(
        `select n.nspname as schema, c.relname as name, ${API_ROLES} as reach
           from pg_class c join pg_namespace n on n.oid = c.relnamespace
          where c.relkind in ('r', 'p') and c.relrowsecurity and n.nspname = any($1)
            and not exists (select 1 from pg_policy p where p.polrelid = c.oid)`,
        [schemas],
      );
      return rows
        .filter((r) => r.reach)
        .map((r) => ({
          ruleId: "SS002",
          severity: "info" as Severity,
          message: `${r.schema}.${r.name} has RLS enabled but no policies, so the API can't access any row.`,
          object: { kind: "table", schema: r.schema, name: r.name },
        }));
    },
  },
  {
    id: "SS003",
    name: "permissive-policy",
    title: "Policy that allows every row",
    description: "A USING (true) or WITH CHECK (true) policy turns RLS off for the roles it applies to.",
    remediation: "Scope the policy to the rows the caller owns, e.g. using ((select auth.uid()) = user_id).",
    async run({ db, schemas }) {
      const { rows } = await db.query<{ schema: string; tbl: string; name: string; cmd: string; roles: string[] }>(
        `select schemaname as schema, tablename as tbl, policyname as name, cmd, roles::text[] as roles
           from pg_policies
          where schemaname = any($1)
            and permissive = 'PERMISSIVE'
            and (btrim(coalesce(qual, '')) = 'true' or btrim(coalesce(with_check, '')) = 'true')`,
        [schemas],
      );
      return rows.map((r) => {
        const open = r.roles.some((role) => role === "anon" || role === "public");
        // Public read-only data (a product catalog, a blog) is a legit use; writes never are.
        const severity: Severity = r.cmd === "SELECT" ? (open ? "high" : "medium") : open ? "critical" : "high";
        return {
          ruleId: "SS003",
          severity,
          message: `Policy "${r.name}" (${r.cmd}) on ${r.schema}.${r.tbl} allows every row for ${r.roles.join(", ")}.`,
          object: { kind: "policy", schema: r.schema, name: r.name, table: r.tbl },
        };
      });
    },
  },
  {
    id: "SS004",
    name: "policy-trusts-user-metadata",
    title: "Policy trusts user_metadata",
    description:
      "user_metadata (raw_user_meta_data) can be changed by the user with supabase.auth.updateUser(), so anyone can grant themselves whatever the policy checks for.",
    remediation: "Keep roles in app_metadata (only the server can write it) or in your own table.",
    docs: "https://supabase.com/docs/guides/database/postgres/row-level-security#authjwt",
    async run({ db, schemas }) {
      const { rows } = await db.query<{ schema: string; tbl: string; name: string }>(
        `select schemaname as schema, tablename as tbl, policyname as name
           from pg_policies
          where schemaname = any($1)
            and (coalesce(qual, '') || coalesce(with_check, '')) ~* '(user_metadata|raw_user_meta_data)'`,
        [schemas],
      );
      return rows.map((r) => ({
        ruleId: "SS004",
        severity: "high" as Severity,
        message: `Policy "${r.name}" on ${r.schema}.${r.tbl} makes decisions based on user-editable user_metadata.`,
        object: { kind: "policy", schema: r.schema, name: r.name, table: r.tbl },
      }));
    },
  },
  {
    id: "SS005",
    name: "definer-mutable-search-path",
    title: "SECURITY DEFINER function without a fixed search_path",
    description:
      "The function runs with its owner's privileges but resolves unqualified names using the caller's search_path, so a caller who can create objects can make it run their code.",
    remediation: "Add `set search_path = ''` to the function and schema-qualify every name inside it.",
    docs: "https://www.postgresql.org/docs/current/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY",
    async run({ db }) {
      const { rows } = await db.query<{ schema: string; name: string; args: string }>(
        `select n.nspname as schema, p.proname as name, pg_get_function_identity_arguments(p.oid) as args
           from pg_proc p join pg_namespace n on n.oid = p.pronamespace
          where p.prosecdef
            and not n.nspname = any($1)
            and not exists (select 1 from pg_depend d where d.objid = p.oid and d.deptype = 'e')
            and not exists (select 1 from unnest(coalesce(p.proconfig, '{}')) cfg where cfg like 'search_path=%')`,
        [SYSTEM_SCHEMAS],
      );
      return rows.map((r) => ({
        ruleId: "SS005",
        severity: "high" as Severity,
        message: `${r.schema}.${r.name}(${r.args}) is SECURITY DEFINER but does not pin search_path.`,
        object: { kind: "function", schema: r.schema, name: r.name },
      }));
    },
  },
  {
    id: "SS006",
    name: "definer-callable-from-api",
    title: "SECURITY DEFINER function callable through the API",
    description:
      "Exposed RPCs that run as the owner bypass RLS. Callable by anon means anyone on the internet can run it.",
    remediation:
      "Move it to a schema that isn't exposed, or `revoke execute ... from public, anon` and check the caller with auth.uid() inside.",
    async run({ db, schemas }) {
      const { rows } = await db.query<{ schema: string; name: string; args: string; anon: boolean; auth: boolean }>(
        `select n.nspname as schema, p.proname as name, pg_get_function_identity_arguments(p.oid) as args,
                has_function_privilege('anon', p.oid, 'execute') and has_schema_privilege('anon', n.oid, 'usage') as anon,
                has_function_privilege('authenticated', p.oid, 'execute') and has_schema_privilege('authenticated', n.oid, 'usage') as auth
           from pg_proc p join pg_namespace n on n.oid = p.pronamespace
          where p.prosecdef and n.nspname = any($1)
            and p.prorettype <> 'trigger'::regtype
            and not exists (select 1 from pg_depend d where d.objid = p.oid and d.deptype = 'e')`,
        [schemas],
      );
      return rows
        .filter((r) => r.anon || r.auth)
        .map((r) => ({
          ruleId: "SS006",
          // Logged-in-only RPCs are a normal pattern (e.g. create_tenant); they just deserve a review.
          severity: (r.anon ? "high" : "low") as Severity,
          message: `${r.schema}.${r.name}(${r.args}) runs as its owner and can be called via RPC by ${r.anon ? "anyone (anon)" : "any logged-in user"}.`,
          object: { kind: "function", schema: r.schema, name: r.name },
        }));
    },
  },
  {
    id: "SS007",
    name: "view-bypasses-rls",
    title: "View that bypasses RLS",
    description:
      "Views run with the privileges of their owner by default, so selecting from the view ignores the RLS policies of the tables underneath.",
    remediation: "alter view <view> set (security_invoker = true);  (Postgres 15+)",
    docs: "https://supabase.com/docs/guides/database/database-linter?lint=0010_security_definer_view",
    async run({ db, schemas }) {
      const { rows } = await db.query<{ schema: string; name: string; reach: string }>(
        `select n.nspname as schema, c.relname as name,
                case
                  when has_table_privilege('anon', c.oid, 'select') and has_schema_privilege('anon', n.oid, 'usage') then 'anon'
                  when has_table_privilege('authenticated', c.oid, 'select') and has_schema_privilege('authenticated', n.oid, 'usage') then 'authenticated'
                end as reach
           from pg_class c join pg_namespace n on n.oid = c.relnamespace
          where c.relkind in ('v', 'm') and n.nspname = any($1)
            and not exists (select 1 from pg_depend d where d.objid = c.oid and d.deptype = 'e')
            and not coalesce(c.reloptions::text[] && array['security_invoker=true', 'security_invoker=on', 'security_invoker=1'], false)`,
        [schemas],
      );
      return rows
        .filter((r) => r.reach)
        .map((r) => ({
          ruleId: "SS007",
          severity: (r.reach === "anon" ? "high" : "medium") as Severity,
          message: `View ${r.schema}.${r.name} is readable by ${r.reach} and runs with its owner's privileges (no security_invoker).`,
          object: { kind: "view", schema: r.schema, name: r.name },
        }));
    },
  },
  {
    id: "SS008",
    name: "public-bucket",
    title: "Public storage bucket",
    description: "Every file in a public bucket can be downloaded by anyone who has (or guesses) its URL, without any policy check.",
    remediation: "Make the bucket private and serve files through signed URLs or storage policies.",
    docs: "https://supabase.com/docs/guides/storage/buckets/fundamentals",
    async run({ db }) {
      const exists = await db.query<{ ok: boolean }>(`select to_regclass('storage.buckets') is not null as ok`);
      if (!exists.rows[0]?.ok) return [];
      const { rows } = await db.query<{ id: string }>(`select id from storage.buckets where public`);
      const sensitive = /(invoice|document|contract|receipt|private|backup|export|report|kyc|id[-_]?card|payslip)/i;
      return rows.map((r) => ({
        ruleId: "SS008",
        severity: (sensitive.test(r.id) ? "high" : "medium") as Severity,
        message: `Storage bucket "${r.id}" is public${sensitive.test(r.id) ? " and its name suggests sensitive files" : ""}.`,
        object: { kind: "bucket", name: r.id },
      }));
    },
  },
  {
    id: "SS009",
    name: "extension-in-exposed-schema",
    title: "Extension installed in an API-exposed schema",
    description: "Extension functions and tables in an exposed schema become part of your public API surface.",
    remediation: "Install extensions into the `extensions` schema: create extension <name> with schema extensions;",
    async run({ db, schemas }) {
      const { rows } = await db.query<{ schema: string; name: string }>(
        `select n.nspname as schema, e.extname as name
           from pg_extension e join pg_namespace n on n.oid = e.extnamespace
          where n.nspname = any($1)`,
        [schemas],
      );
      return rows.map((r) => ({
        ruleId: "SS009",
        severity: "low" as Severity,
        message: `Extension ${r.name} is installed in the exposed schema ${r.schema}.`,
        object: { kind: "extension", schema: r.schema, name: r.name },
      }));
    },
  },
];
