-- Attacks the accounts schema from every role. Run on a fresh database after the shim and the migration.
-- Any failed expectation raises an exception (psql -v ON_ERROR_STOP=1 exits non-zero).
\set ON_ERROR_STOP 1
grant all on all tables in schema public to service_role;
insert into auth.users (id, email, email_confirmed_at) values
  ('00000000-0000-0000-0000-00000000000a', 'a@example.test', now()),
  ('00000000-0000-0000-0000-00000000000b', 'b@example.test', now()),
  ('00000000-0000-0000-0000-00000000000c', 'c@example.test', null);

create or replace function pg_temp.expect_fail(sql text, what text) returns void language plpgsql as $$
begin
  begin execute sql; exception when others then return; end;
  raise exception 'SECURITY TEST FAILED: % was allowed (%)', what, sql;
end $$;
create or replace function pg_temp.expect(cond boolean, what text) returns void language plpgsql as $$
begin if not cond then raise exception 'TEST FAILED: %', what; end if; end $$;
grant execute on all functions in schema pg_temp to anon, authenticated, service_role;

-- ---------- user A sets up their own rows ----------
set role authenticated; select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000a', false);
insert into public.accounts (user_id) values ('00000000-0000-0000-0000-00000000000a');
insert into public.environments (user_id, ciphertext, iv, salt) values ('00000000-0000-0000-0000-00000000000a', 'QUJDREVGR0hJSktMTU5PUA==', 'AAAAAAAAAAAAAAAA', 'BBBBBBBBBBBBBBBB');
select pg_temp.expect(public.cv_terms_ok(array['Fortinet','Ivanti']), 'valid terms accepted');
update public.accounts set alerts_enabled = true, alert_terms = array['Fortinet','Ivanti'], consent_at = now(),
  consent_text = 'Email me alerts', consent_version = '1' where user_id = auth.uid();
select pg_temp.expect((select count(*) from public.accounts) = 1, 'A sees exactly one account row');

-- user A cannot break the rules on their own row
select pg_temp.expect_fail($q$ update public.accounts set alert_terms = array['<script>'] where user_id = auth.uid() $q$, 'markup in alert terms');
select pg_temp.expect_fail($q$ update public.accounts set alert_terms = (select array_agg('term'||g) from generate_series(1,151) g) where user_id = auth.uid() $q$, 'more than 150 terms');
select pg_temp.expect_fail($q$ update public.accounts set alerts_enabled = true, consent_at = null where user_id = auth.uid() $q$, 'alerts without consent');
select pg_temp.expect_fail($q$ update public.accounts set unsubscribe_token = gen_random_uuid() where user_id = auth.uid() $q$, 'changing own unsubscribe token');
select pg_temp.expect_fail($q$ update public.accounts set last_alert_at = now() where user_id = auth.uid() $q$, 'changing last_alert_at');
select pg_temp.expect_fail($q$ insert into public.alert_log (user_id, event_id) values (auth.uid(), 'x') $q$, 'writing the alert log');
select pg_temp.expect_fail($q$ update public.environments set ciphertext = 'not base64 <>' where user_id = auth.uid() $q$, 'non-base64 ciphertext');
select pg_temp.expect_fail($q$ select * from public.alert_recipients() $q$, 'user calling alert_recipients');
select pg_temp.expect_fail($q$ select * from auth.users $q$, 'user reading auth.users');

-- ---------- user B cannot see or touch A ----------
select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000b', false);
select pg_temp.expect((select count(*) from public.accounts) = 0, 'B sees no account rows of A');
select pg_temp.expect((select count(*) from public.environments) = 0, 'B sees no environment rows of A');
update public.accounts set alerts_enabled = false where user_id = '00000000-0000-0000-0000-00000000000a';
delete from public.environments where user_id = '00000000-0000-0000-0000-00000000000a';
select pg_temp.expect_fail($q$ insert into public.accounts (user_id) values ('00000000-0000-0000-0000-00000000000a') $q$, 'B creating a row for A');
select pg_temp.expect_fail($q$ insert into public.environments (user_id, ciphertext, iv, salt) values ('00000000-0000-0000-0000-00000000000a','QUJDREVGR0hJSktMTU5PUA==','AAAAAAAAAAAAAAAA','BBBBBBBBBBBBBBBB') $q$, 'B writing A''s environment');
select pg_temp.expect((public.export_my_data() -> 'account' ->> 'email') = 'b@example.test', 'B export contains only B');
select pg_temp.expect((public.export_my_data() ->> 'settings') is null, 'B export has no settings of A');

-- ---------- anonymous visitor ----------
reset role; select set_config('request.jwt.claim.sub', '', false); set role anon;
select pg_temp.expect_fail($q$ select * from public.accounts $q$, 'anon reading accounts');
select pg_temp.expect_fail($q$ select * from public.environments $q$, 'anon reading environments');
select pg_temp.expect_fail($q$ select * from public.alert_log $q$, 'anon reading alert_log');
select pg_temp.expect_fail($q$ select public.export_my_data() $q$, 'anon exporting');
select pg_temp.expect_fail($q$ select public.delete_my_account() $q$, 'anon deleting');
select pg_temp.expect_fail($q$ select * from public.alert_recipients() $q$, 'anon listing recipients');
select pg_temp.expect(public.unsubscribe(gen_random_uuid()) = false, 'unsubscribe with an unknown token does nothing');

-- ---------- the alerts job ----------
reset role; set role service_role;
select pg_temp.expect((select count(*) from public.accounts where user_id = '00000000-0000-0000-0000-00000000000a' and alerts_enabled) = 1, 'B''s attempts left A untouched');
select pg_temp.expect((select count(*) from public.environments) = 1, 'A''s environment survived B''s delete');
select pg_temp.expect((select count(*) from public.alert_recipients()) = 1, 'one recipient (confirmed email, consent given)');
insert into public.alert_log (user_id, event_id) values ('00000000-0000-0000-0000-00000000000a', 'evt-1');

-- one-click unsubscribe works without signing in
select unsubscribe_token as tok from public.accounts where user_id = '00000000-0000-0000-0000-00000000000a' \gset
reset role; set role anon;
select pg_temp.expect(public.unsubscribe(:'tok') = true, 'unsubscribe with the right token');
reset role; set role service_role;
select pg_temp.expect((select not alerts_enabled and unsubscribed_at is not null from public.accounts where user_id = '00000000-0000-0000-0000-00000000000a'), 'alerts off after unsubscribe');
select pg_temp.expect((select count(*) from public.alert_recipients()) = 0, 'no recipients after unsubscribe');

-- delete my account removes everything A owns
reset role; set role authenticated; select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000a', false);
select pg_temp.expect(jsonb_array_length(public.export_my_data() -> 'alerts_sent') = 1, 'A export lists alerts sent');
select pg_temp.expect((public.export_my_data() -> 'settings' ->> 'unsubscribe_token') is null and (public.export_my_data() -> 'settings' ->> 'alerts_enabled') = 'false', 'export hides the unsubscribe token');
select public.delete_my_account();
reset role;
select pg_temp.expect((select count(*) from auth.users where id = '00000000-0000-0000-0000-00000000000a') = 0, 'auth user deleted');
select pg_temp.expect((select count(*) from public.accounts where user_id = '00000000-0000-0000-0000-00000000000a') = 0, 'account row deleted');
select pg_temp.expect((select count(*) from public.environments where user_id = '00000000-0000-0000-0000-00000000000a') = 0, 'environment deleted');
select pg_temp.expect((select count(*) from public.alert_log where user_id = '00000000-0000-0000-0000-00000000000a') = 0, 'alert log deleted');
\echo 'SQL SECURITY TESTS: ALL PASS'
