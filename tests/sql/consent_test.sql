-- The consent record is set by the database (supabase/migrations/0002_consent_trigger.sql). Run after rls_test.sql
-- and the 0002 migration. Any failed expectation raises an exception.
\set ON_ERROR_STOP 1
insert into auth.users (id, email, email_confirmed_at) values
  ('00000000-0000-0000-0000-0000000000d1', 'd@example.test', now()) on conflict do nothing;
create or replace function pg_temp.expect_fail(sql text, what text) returns void language plpgsql as $$
begin
  begin execute sql; exception when others then return; end;
  raise exception 'SECURITY TEST FAILED: % was allowed (%)', what, sql;
end $$;
create or replace function pg_temp.expect(cond boolean, what text) returns void language plpgsql as $$
begin if not cond then raise exception 'TEST FAILED: %', what; end if; end $$;
grant execute on all functions in schema pg_temp to anon, authenticated, service_role;

set role authenticated; select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-0000000000d1', false);
-- an insert cannot plant a consent record without turning alerts on
insert into public.accounts (user_id, consent_at, consent_text, consent_version)
  values ('00000000-0000-0000-0000-0000000000d1', now() - interval '1 year', 'I agreed to anything', '1');
select pg_temp.expect((select consent_at is null and consent_text is null from public.accounts where user_id = auth.uid()), 'insert without alerts stores no consent');

-- turning alerts on: back-dated time and made-up wording are replaced by now() and the stored wording
update public.accounts set alerts_enabled = true, alert_terms = array['Fortinet'], consent_at = now() - interval '1 year',
  consent_text = 'I agreed to anything', consent_version = '1' where user_id = auth.uid();
select pg_temp.expect((select consent_at > now() - interval '1 minute' from public.accounts where user_id = auth.uid()), 'consent time is the database''s now()');
select pg_temp.expect((select consent_text like 'Yes, email me CyberView alerts%' from public.accounts where user_id = auth.uid()), 'consent wording is the stored version 1 wording');

-- afterwards the record cannot be rewritten
update public.accounts set consent_at = now() - interval '5 years', consent_text = 'changed' where user_id = auth.uid();
select pg_temp.expect((select consent_at > now() - interval '1 minute' and consent_text like 'Yes, email me%' from public.accounts where user_id = auth.uid()), 'consent record cannot be rewritten');

-- an unknown version is refused; nobody can read or add consent versions
select pg_temp.expect_fail($q$ update public.accounts set consent_version = '99' where user_id = auth.uid() $q$, 'unknown consent version');
select pg_temp.expect_fail($q$ select * from public.consent_versions $q$, 'user reading consent_versions');
select pg_temp.expect_fail($q$ insert into public.consent_versions (version, wording) values ('2', 'x') $q$, 'user adding a consent version');

-- turning alerts off keeps the record (it is the evidence of what was agreed)
update public.accounts set alerts_enabled = false where user_id = auth.uid();
select pg_temp.expect((select consent_text is not null from public.accounts where user_id = auth.uid()), 'turning alerts off keeps the consent record');

reset role;
select 'CONSENT TESTS: ALL PASS';
