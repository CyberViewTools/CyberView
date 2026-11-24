-- CyberView accounts: the consent record is written by the database, not by the browser (pen test, 2026-11-24).
-- Before this, a signed-in user calling the API directly could store any consent time (back-dated), any wording and any
-- version. Now, whatever the client sends:
--   * when alerts are turned on (or the consent version changes), consent_at is the database's now() and consent_text is
--     the wording stored here for that consent_version; an unknown version is refused;
--   * at any other time the three consent columns keep their stored values (a user cannot rewrite their own record).
-- Idempotent: safe to run more than once.

create table if not exists public.consent_versions (
  version  text primary key check (length(version) <= 20),
  wording  text not null check (length(wording) <= 600),
  added_at timestamptz not null default now()
);
alter table public.consent_versions enable row level security;
alter table public.consent_versions force row level security;
revoke all on public.consent_versions from public, anon, authenticated;

-- version 1: the wording on pages/account.html (#consentText). A new wording is a new version row, never an edit.
insert into public.consent_versions (version, wording) values
  ('1', 'Yes, email me CyberView alerts about these terms at my account address. I can unsubscribe at any time with the link in every email.')
on conflict (version) do nothing;

create or replace function public.cv_consent_guard() returns trigger
language plpgsql security definer set search_path = '' as $$
declare w text;
begin
  if new.alerts_enabled and (tg_op = 'INSERT' or not old.alerts_enabled or new.consent_version is distinct from old.consent_version) then
    select v.wording into w from public.consent_versions v where v.version = new.consent_version;
    if w is null then raise exception 'unknown consent version %', coalesce(new.consent_version, '(none)'); end if;
    new.consent_at := now();
    new.consent_text := w;
  elsif tg_op = 'UPDATE' then
    new.consent_at := old.consent_at;
    new.consent_text := old.consent_text;
    new.consent_version := old.consent_version;
  else
    new.consent_at := null; new.consent_text := null; new.consent_version := null;
  end if;
  return new;
end $$;
revoke all on function public.cv_consent_guard() from public, anon, authenticated;

drop trigger if exists cv_consent_guard on public.accounts;
create trigger cv_consent_guard before insert or update on public.accounts
  for each row execute function public.cv_consent_guard();
