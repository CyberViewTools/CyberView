# Accounts: design, security and setup

Accounts are optional. Everything on the map works without one. An account adds two things:

1. **Encrypted sync** of the "My environment" list across devices.
2. **Email alerts** when a new event or known-exploited flaw matches the user's alert terms.

## Architecture

| Part | Where | Notes |
|---|---|---|
| Sign-in | Supabase Auth | Magic email link (no passwords) and optional GitHub login. PKCE flow. Session kept in the browser's local storage. |
| Database | Supabase Postgres | `supabase/migrations/0001_accounts.sql`: tables `accounts`, `environments`, `alert_log`, row-level security and four functions |
| Account pages | `pages/account.html`, `pages/unsubscribe.html` -> `site/` (built by `scripts/pages.mjs`) | The only pages that load `vendor/supabase.min.js` and may connect to the Supabase project |
| Alerts | `scripts/alerts.mjs`, `.github/workflows/alerts.yml` | Hourly. Uses the service key and the email provider key from GitHub secrets. Commits nothing. |
| Config | `config/accounts.json` (public URL and anon key), `config/site.json` (contact, mailing address, email provider) | Never put a secret in either; `scripts/pages.mjs` refuses a service key |

## Security model

- **Row-level security on every table, forced.** A signed-in user reaches only rows where `user_id = auth.uid()`. The anonymous role has no table access; it can call only `unsubscribe(token)`.
- **Least privilege by column.** Users can change their own settings, but not their unsubscribe token or the alert bookkeeping. Only the alerts job (service role) writes the alert log.
- **Constraints in the database, not just the page.** At most 150 alert terms, each 2 to 60 characters with no markup or control characters. Ciphertext must be base64 and capped in size. Alerts cannot be on without a recorded consent.
- **End-to-end encrypted sync.**
  - In the browser: PBKDF2-SHA256 with 600,000 iterations (the OWASP 2023 figure), then AES-GCM-256.
  - A random 16-byte salt and a random 12-byte nonce for every save.
  - The server stores ciphertext only; neither the passphrase nor the plain list is ever sent. A lost passphrase cannot be recovered.
- **Alert terms are stored readable**, because the server must match them. This happens only after an explicit, unticked-by-default consent; the wording, version and time of that consent are stored with them.
- **Unsubscribe without sign-in.** Each account has a random 122-bit token. The link needs a button press, so email scanners that follow links do not unsubscribe people. The token is removed from the address bar after the page loads.
- **The security policy stays strict.**
  - The map and every other page keep `connect-src 'self'`.
  - The two account pages add exactly the configured `https://<ref>.supabase.co`, which `scripts/security-check.mjs` enforces.
  - The Supabase library is pinned by SHA-256 like d3, and may be loaded by the account pages only.
- **No user enumeration.** The sign-in form shows the same message whether or not an address has an account.
- **Tested.**
  - `tests/sql/rls_test.sql` attacks the schema from the anonymous role, from another user and from the alerts job, on a fresh Postgres in CI (`build.yml`, job `sql-security-tests`).
  - `tests/test_all.py` drives the account page against a fake Supabase. It checks that only ciphertext leaves the browser, that a wrong passphrase fails, that consent is required, and that export and delete work.
  - `tests/unit/alerts.test.mjs` covers matching, the anti-spam (CASL) elements and HTML escaping in the emails.

Accepted risks, with their mitigations:
- A script injected into the account page could read the session. Mitigations: a strict CSP, no HTML string sinks, a pinned library, and no third-party scripts.
- Supabase staff and anyone holding the service key can read alert terms and email addresses. Mitigations: keep the service key only in GitHub secrets, and keep the terms to vendor and product names.

## Setup (owner, once)

1. **Create the project.**
   - Sign in at https://supabase.com and choose **New project**. Name it `cyberview`, choose region **Canada (Central)**, and store the generated database password in a password manager.
2. **Create the schema.**
   - Open **SQL Editor**, choose **New query**, paste the whole of `supabase/migrations/0001_accounts.sql`, and press **Run**. It is safe to run again.
3. **Set up sign-in.**
   - Under **Authentication → URL Configuration**, set **Site URL** to `https://xanderhutch.github.io/CyberView/account.html` and add the same address under **Redirect URLs**.
   - Under **Authentication → Providers → Email**, keep **Confirm email** on and set **OTP expiry** to 3600 seconds.
   - **Authentication → SMTP Settings**: Supabase's built-in mailer only sends a few emails an hour and is meant for testing. Turn on **Custom SMTP** with Brevo (SMTP server `smtp-relay.brevo.com`, port 587, your Brevo SMTP login and key, sender = your verified sender address).
   - Optional, for GitHub login: create a GitHub OAuth app at https://github.com/settings/developers.
     - Callback URL: `https://<ref>.supabase.co/auth/v1/callback`.
     - Enter the app's client ID and secret under **Authentication → Providers → GitHub**.
     - Then set `github_login` to `true` in `config/accounts.json`.
4. **Connect the site.**
   - Under **Settings → API**, copy the **Project URL** and the **anon public** key into `config/accounts.json`, and set `region`.
   - Both values are public by design. **Never** copy the `service_role` key there; the build refuses it.
5. **Set up email alerts.**
   - Create a free Brevo account, verify the sender email address you will send from (a dedicated address, not your personal inbox), and create an API key.
   - In GitHub, under **CyberView → Settings → Secrets and variables → Actions**, add these secrets:
     - `SUPABASE_SERVICE_ROLE_KEY`, from Supabase **Settings → API**
     - `BREVO_API_KEY`
     - `ALERT_FROM_EMAIL`
6. **Fill in the legal details** in `config/site.json`:
   - `contact_email`: a dedicated address for privacy, corrections and takedown requests.
   - `mailing_address`: a postal address or PO box. Required in every alert email by CASL; the alerts job will not send without it.
7. **Turn on private vulnerability reporting**, which `security.txt` and the About page point to: **Settings → Code security → Private vulnerability reporting → Enable**.
8. **Check it end to end.**
   - Push. Then sign in on the live account page, save an encrypted copy, turn alerts on, and start **Actions → Email alerts → Run workflow**.
   - Confirm the email arrives with a working unsubscribe link.

## Operating

- **Alerts** run hourly. Each user gets them at the chosen frequency (instant means at most hourly, daily or weekly), at most 20 items per email, never the same event twice. History is purged after 90 days.
- **Data requests** are self-service on the account page: export, delete, alerts off, sync removed. For a request by email, verify that it comes from the account's address before acting.
- **Breaches**: if personal information may have been exposed, assess the risk of significant harm.
  - If the risk is real, notify the affected users and the Office of the Privacy Commissioner of Canada as soon as feasible, and keep a record of every breach (PIPEDA).
  - For users in the EU or UK, notify the regulator within 72 hours where the GDPR requires it.
  - In any case, rotate the service key in Supabase and update the GitHub secret.
- **Changing a policy**: edit `legal/*.html` and bump `legal_updated` in `config/site.json`. For a material change, email account holders before it takes effect.
