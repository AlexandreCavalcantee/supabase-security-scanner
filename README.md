# supabase-security-scanner

[![CI](https://github.com/AlexandreCavalcantee/supabase-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/AlexandreCavalcantee/supabase-security-scanner/actions/workflows/ci.yml)

Find the Supabase misconfigurations that leak data — **before** they ship.

Supabase puts your database one HTTP request away from the browser. That's what makes it fast to build with,
and it's also why a single table without Row Level Security, a `using (true)` policy or a `service_role` key in a
JavaScript bundle is enough to expose everything. This scanner checks for those mistakes in three ways:

| Mode     | Looks at                                  | Finds                                                                                         |
| -------- | ----------------------------------------- | --------------------------------------------------------------------------------------------- |
| `db`     | the Postgres catalog (read-only session)  | RLS gaps, permissive policies, unsafe `SECURITY DEFINER` functions, views that bypass RLS, … |
| `bundle` | the JavaScript your deployed site serves  | `service_role` / `sb_secret_` keys and other credentials shipped to the browser              |
| `probe`  | your live API, using **only the public key** | tables that actually return rows to anonymous requests                                       |

Findings point at the **migration line** that created the object, and the SARIF output shows up in GitHub's
Security tab and as annotations on pull requests.

```
$ supabase-scan db --db-url $SUPABASE_DB_URL --schemas public

 CRITICAL  SS001 Table exposed through the API without Row Level Security
           RLS is disabled on public.customers and the anon role has access to it.
           at supabase/migrations/20261020000001_init.sql:14
           fix: alter table <table> enable row level security; then add policies for the access you actually want.

 HIGH      SS004 Policy trusts user_metadata
           Policy "admins only" on public.admin_settings makes decisions based on user-editable user_metadata.
           at supabase/migrations/20261020000001_init.sql:37
           fix: Keep roles in app_metadata (only the server can write it) or in your own table.
 ...
9 findings: 1 critical, 6 high, 1 low, 1 info
```

## Rules

| ID    | Severity          | What it catches                                                                                     |
| ----- | ----------------- | --------------------------------------------------------------------------------------------------- |
| SS001 | critical / high   | Table reachable through the API with **RLS disabled** (critical when `anon` has access)             |
| SS002 | info              | RLS enabled but **no policies** — locked, usually a forgotten policy                               |
| SS003 | critical → medium | Policy with `using (true)` / `with check (true)`; worse for `anon` and for writes                   |
| SS004 | high              | Policy that trusts **`user_metadata`**, which users can edit with `auth.updateUser()`                |
| SS005 | high              | `SECURITY DEFINER` function without a pinned **`search_path`** (search-path hijacking)              |
| SS006 | high / low        | `SECURITY DEFINER` function **callable via RPC** (high for `anon`, review for logged-in users)      |
| SS007 | high / medium     | **View that bypasses RLS** (no `security_invoker`) readable through the API                         |
| SS008 | high / medium     | **Public storage bucket** (high when the name suggests invoices, documents, KYC…)                    |
| SS009 | low               | Extension installed in an API-exposed schema                                                        |
| SS101 | critical / high   | **Secret in the front-end bundle**: `service_role` JWT, `sb_secret_…`, Stripe live, AWS, GitHub…     |
| SS201 | high              | Table that **returns rows to the public key** on the live API                                       |

`supabase-scan rules` prints the list; every finding comes with a concrete fix.

## Usage

```bash
npx github:AlexandreCavalcantee/supabase-security-scanner db --db-url postgresql://postgres:postgres@127.0.0.1:54322/postgres
```

```
supabase-scan db     --db-url <url> [--schemas public,api] [--migrations supabase/migrations]
supabase-scan bundle --url https://your-app.com
supabase-scan probe  --url https://<ref>.supabase.co --anon-key <public key> [--schemas public]

--format text|json|sarif   --output <file>   --fail-on <severity|none>   --min-severity <severity>
```

`SUPABASE_DB_URL`, `SUPABASE_URL` and `SUPABASE_ANON_KEY` can replace the flags. Exit code is `1` when something at
or above `--fail-on` (default `high`) is found, `2` on usage or connection errors.

### In GitHub Actions

Scan the migrations of every pull request against a throwaway local database:

```yaml
jobs:
  supabase-security:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # to upload SARIF
    steps:
      - uses: actions/checkout@v5
      - uses: supabase/setup-cli@v1
      - run: supabase db start   # applies supabase/migrations

      - uses: AlexandreCavalcantee/supabase-security-scanner@main
        with:
          schemas: public
          fail-on: high

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: supabase-scan.sarif
```

## Safety

- `db` opens a **read-only** session; a test proves a rule that tries to write gets an error instead.
- `probe` only sends `GET` requests with the key you give it, to the project you point it at. Use it on projects
  you own or are authorized to test.
- `bundle` only downloads same-origin scripts, and secrets are always **redacted** in the output
  (`sb_secret_N…Pvz`), so reports are safe to paste in a ticket.

## How it's tested

[`fixtures/supabase`](fixtures/supabase/migrations) is a real Supabase project with two schemas:

- **`vuln`** — one deliberate mistake per rule. The integration test asserts the scanner reports exactly that set.
- **`secure`** — the same features done right. The test asserts zero findings.

CI starts the fixture stack, runs the unit tests (secret detection, redaction, migration mapping, SARIF shape) and
the integration tests against the database and the live API, then runs the GitHub Action on the fixtures and checks
the SARIF it produces.

It was also run against [supabase-multitenant-saas](https://github.com/AlexandreCavalcantee/supabase-multitenant-saas):
no high or critical findings — only two logged-in-only RPCs flagged for review, which are intentional.

## Development

```bash
npm install
supabase start --workdir fixtures      # fixture stack on ports 553xx
npm run build && npm test              # integration tests need the SCANNER_TEST_* vars, see .github/workflows/ci.yml
```

## Why I built it

While reviewing one of my own projects I found API routes using the `service_role` key with no auth check at all:
anyone with the URL could list profiles and create users. It was an easy mistake to make and an easy one to miss in
review. This tool is the checklist I wish had run in CI.

## License

MIT © Alexandre Cavalcante
