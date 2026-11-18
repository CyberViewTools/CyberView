-- CyberView accounts: schema, row-level security and functions.
-- Apply once in the Supabase dashboard (SQL Editor -> New query -> paste -> Run), or with `supabase db push`.
-- Safe to re-run: every statement is idempotent.
--
-- Design (see docs/accounts.md):
--   * Every table has row-level security; a signed-in user can reach only rows where user_id = auth.uid().
--   * The anonymous role can touch no table. It can call exactly one function: unsubscribe(token).
--   * The synced environment is ciphertext made in the browser (AES-GCM, key from the user's passphrase);
--     the server never sees the passphrase or the plain list.
--   * Alert terms are stored in plain form only when the user turns alerts on, with the consent wording and time.
--   * Deleting the auth user cascades to every row the user owns.

create extension if not exists pgcrypto;

-- every alert term: 2 to 60 characters, no control characters or angle brackets; at most 150 terms
create or replace function public.cv_terms_ok(t text[]) returns boolean
language sql immutable set search_path = '' as $$
  select coalesce(cardinality(t), 0) <= 150
     and coalesce((select bool_and(length(x) between 2 and 60 and x !~ '[<>[:cntrl:]]') from unnest(t) as x), true)
$$;

create table if not exists public.accounts (
  user_id            uuid primary key references auth.users (id) on delete cascade,
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now(),
  alerts_enabled     boolean not null default false,
  alert_frequency    text not null default 'daily' check (alert_frequency in ('instant', 'daily', 'weekly')),
  alert_min_severity smallint not null default 2 check (alert_min_severity between 1 and 3),
  alert_terms        text[] not null default '{}' check (public.cv_terms_ok(alert_terms)),
  consent_at         timestamptz,
  consent_text       text check (length(consent_text) <= 600),
  consent_version    text check (length(consent_version) <= 20),
  unsubscribed_at    timestamptz,
  unsubscribe_token  uuid not null default gen_random_uuid() unique,
  last_alert_at      timestamptz,
  -- alerts can be on only with a recorded consent
  constraint alerts_need_consent check (not alerts_enabled or (consent_at is not null and consent_text is not null))
);

create table if not exists public.environments (
  user_id    uuid primary key references auth.users (id) on delete cascade,
  ciphertext text not null check (length(ciphertext) between 16 and 200000 and ciphertext ~ '^[A-Za-z0-9+/=]+$'),
  iv         text not null check (length(iv) between 8 and 64 and iv ~ '^[A-Za-z0-9+/=]+$'),
  salt       text not null check (length(salt) between 8 and 64 and salt ~ '^[A-Za-z0-9+/=]+$'),
  kdf        text not null default 'PBKDF2-SHA256-600000' check (kdf in ('PBKDF2-SHA256-600000')),
  updated_at timestamptz not null default now()
);

create table if not exists public.alert_log (
  user_id  uuid not null references auth.users (id) on delete cascade,
  event_id text not null check (length(event_id) between 1 and 160),
  sent_at  timestamptz not null default now(),
  primary key (user_id, event_id)
);
create index if not exists alert_log_sent_at on public.alert_log (sent_at);

create or replace function public.cv_touch() returns trigger language plpgsql set search_path = '' as $$
begin new.updated_at := now(); return new; end $$;
drop trigger if exists accounts_touch on public.accounts;
create trigger accounts_touch before update on public.accounts for each row execute function public.cv_touch();
drop trigger if exists environments_touch on public.environments;
create trigger environments_touch before update on public.environments for each row execute function public.cv_touch();

-- ---------- row-level security ----------
alter table public.accounts     enable row level security;
alter table public.environments enable row level security;
alter table public.alert_log    enable row level security;
alter table public.accounts     force row level security;
alter table public.environments force row level security;
alter table public.alert_log    force row level security;

-- start from nothing, then grant the minimum
revoke all on public.accounts, public.environments, public.alert_log from anon, authenticated, public;

grant select on public.accounts to authenticated;
grant insert (user_id, alerts_enabled, alert_frequency, alert_min_severity, alert_terms, consent_at, consent_text, consent_version)
  on public.accounts to authenticated;
grant update (alerts_enabled, alert_frequency, alert_min_severity, alert_terms, consent_at, consent_text, consent_version, unsubscribed_at)
  on public.accounts to authenticated;
grant select, insert, update, delete on public.environments to authenticated;
grant select on public.alert_log to authenticated;

drop policy if exists accounts_own on public.accounts;
create policy accounts_own on public.accounts for all to authenticated
  using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));
drop policy if exists environments_own on public.environments;
create policy environments_own on public.environments for all to authenticated
  using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));
drop policy if exists alert_log_read_own on public.alert_log;
create policy alert_log_read_own on public.alert_log for select to authenticated
  using (user_id = (select auth.uid()));

-- ---------- functions ----------
-- Everything about the signed-in user, for "Export my data".
create or replace function public.export_my_data() returns jsonb
language sql stable security definer set search_path = '' as $$
  select jsonb_build_object(
    'exported_at', now(),
    'account', (select jsonb_build_object('email', u.email, 'created_at', u.created_at, 'last_sign_in_at', u.last_sign_in_at,
                                          'sign_in_methods', u.raw_app_meta_data -> 'providers')
                from auth.users u where u.id = auth.uid()),
    'settings', (select to_jsonb(a) - 'unsubscribe_token' from public.accounts a where a.user_id = auth.uid()),
    'environment_encrypted', (select to_jsonb(e) from public.environments e where e.user_id = auth.uid()),
    'alerts_sent', coalesce((select jsonb_agg(jsonb_build_object('event_id', l.event_id, 'sent_at', l.sent_at) order by l.sent_at desc)
                             from public.alert_log l where l.user_id = auth.uid()), '[]'::jsonb)
  ) where auth.uid() is not null
$$;

-- "Delete my account": removes the auth user; every owned row goes with it (on delete cascade).
create or replace function public.delete_my_account() returns boolean
language plpgsql security definer set search_path = '' as $$
declare uid uuid := auth.uid();
begin
  if uid is null then raise exception 'not signed in'; end if;
  delete from auth.users where id = uid;
  return true;
end $$;

-- One-click unsubscribe from an email link, without signing in. The token is a random UUID (122 bits).
create or replace function public.unsubscribe(token uuid) returns boolean
language plpgsql security definer set search_path = '' as $$
declare n int;
begin
  update public.accounts set alerts_enabled = false, unsubscribed_at = now()
   where unsubscribe_token = token and alerts_enabled;
  get diagnostics n = row_count;
  return n > 0 or exists (select 1 from public.accounts where unsubscribe_token = token);
end $$;

-- For the alerts job only (service role): who gets alerts, with a confirmed email.
create or replace function public.alert_recipients() returns table (
  user_id uuid, email text, alert_terms text[], alert_frequency text, alert_min_severity smallint,
  unsubscribe_token uuid, last_alert_at timestamptz)
language sql stable security definer set search_path = '' as $$
  select a.user_id, u.email::text, a.alert_terms, a.alert_frequency, a.alert_min_severity, a.unsubscribe_token, a.last_alert_at
    from public.accounts a join auth.users u on u.id = a.user_id
   where a.alerts_enabled and a.consent_at is not null and u.email_confirmed_at is not null and u.deleted_at is null
$$;

revoke all on function public.export_my_data(), public.delete_my_account(), public.unsubscribe(uuid), public.alert_recipients(),
  public.cv_terms_ok(text[]), public.cv_touch() from public, anon, authenticated;
grant execute on function public.export_my_data()    to authenticated;
grant execute on function public.delete_my_account() to authenticated;
grant execute on function public.unsubscribe(uuid)   to anon, authenticated;
grant execute on function public.alert_recipients()  to service_role;
grant execute on function public.cv_terms_ok(text[]) to authenticated, service_role;
