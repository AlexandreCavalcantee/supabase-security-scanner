-- =============================================================================
-- Test fixtures. DO NOT copy anything from the "vuln" schema: every object in
-- it is deliberately insecure, one per scanner rule. The "secure" schema shows
-- the fixed version and must produce no high/critical findings.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- vuln: one mistake per rule
-- -----------------------------------------------------------------------------
create schema vuln;
grant usage on schema vuln to anon, authenticated;

-- SS001: table reachable through the API with RLS off.
create table vuln.customers (
  id    bigint generated always as identity primary key,
  name  text not null,
  email text not null
);
grant select, insert on vuln.customers to anon, authenticated;

-- SS003: RLS on, but the policy lets anyone read everything.
create table vuln.invoices (
  id          bigint generated always as identity primary key,
  customer_id bigint not null,
  amount      numeric not null
);
alter table vuln.invoices enable row level security;
create policy "anyone can read invoices" on vuln.invoices for select to anon, authenticated using (true);
grant select on vuln.invoices to anon, authenticated;

-- SS004: authorization based on user_metadata, which the user can edit themselves.
create table vuln.admin_settings (
  key   text primary key,
  value text
);
alter table vuln.admin_settings enable row level security;
create policy "admins only" on vuln.admin_settings for all to authenticated
  using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');
grant select, update on vuln.admin_settings to authenticated;

-- SS002: RLS on with no policies (locked; usually a forgotten policy).
create table vuln.audit_log (
  id  bigint generated always as identity primary key,
  msg text
);
alter table vuln.audit_log enable row level security;
grant select on vuln.audit_log to authenticated;

-- SS005 + SS006: SECURITY DEFINER without a fixed search_path, callable by anon.
create function vuln.promote_to_admin(p_user uuid)
returns void
language sql
security definer
as $$ update vuln.admin_settings set value = p_user::text where key = 'admin' $$;
grant execute on function vuln.promote_to_admin(uuid) to anon;

-- SS007: a view runs as its owner, so it bypasses the RLS of the table below.
create view vuln.all_invoices as select * from vuln.invoices;
grant select on vuln.all_invoices to anon;

-- SS009: extension installed into an API-exposed schema.
create extension if not exists citext with schema public;

insert into vuln.customers (name, email) values ('Ada', 'ada@example.com'), ('Linus', 'linus@example.com');
insert into vuln.invoices (customer_id, amount) values (1, 100), (2, 250);

-- SS008: public storage bucket with a sensitive-looking name.
do $$
begin
  if to_regclass('storage.buckets') is not null then
    insert into storage.buckets (id, name, public) values ('invoices', 'invoices', true);
  end if;
end
$$;

-- -----------------------------------------------------------------------------
-- secure: the same ideas done right
-- -----------------------------------------------------------------------------
create schema secure;
grant usage on schema secure to anon, authenticated;

create table secure.notes (
  id       bigint generated always as identity primary key,
  owner_id uuid not null default auth.uid(),
  body     text not null
);
create index notes_owner_idx on secure.notes (owner_id);
alter table secure.notes enable row level security;
create policy "owners read their notes" on secure.notes for select to authenticated
  using ((select auth.uid()) = owner_id);
create policy "owners write their notes" on secure.notes for insert to authenticated
  with check ((select auth.uid()) = owner_id);
grant select, insert on secure.notes to authenticated;

-- RLS is enforced for the caller because the view is security_invoker.
create view secure.my_notes with (security_invoker = true) as
  select id, body from secure.notes;
grant select on secure.my_notes to authenticated;

-- Definer function done right: pinned search_path, not callable from the API.
create function secure.count_notes()
returns bigint
language sql
security definer
set search_path = ''
as $$ select count(*) from secure.notes $$;
revoke execute on function secure.count_notes() from public, anon, authenticated;
