# Legal and compliance checklist

This is a working checklist for running CyberView responsibly. It is **not legal advice**. Before relying on it, especially before accounts and alerts go live, have the policies reviewed by a lawyer in Ontario. Status: ✅ done in the code, 🟡 needs the owner, ⬜ later or optional.

## Publishing cyber security news

| Area | Risk | What CyberView does | Status |
|---|---|---|---|
| Defamation | Saying an organisation was breached when it was not | Facts only from sources actually read, each source linked. Attacker claims are labelled "unverified claim" with severity 1 and hidden by default. Denials are recorded, and corrections are logged publicly. A private correction and removal route is on the About page. | ✅ |
| Copyright | Copying articles | Summaries are written in our own words with short, attributed quotes only, and link to the original. Fair dealing for news reporting applies in Canada. | ✅ |
| Takedown requests | Rights holders or named parties asking for removal | Private contact on the About page (needs `contact_email`). Review promptly; correct or remove what is inaccurate or unlawful. | 🟡 contact email |
| Leak-site data | Spreading stolen personal data | Only organisation names from leak-site listings; never files, samples or personal data. Stated in the privacy policy. | ✅ |
| People named in events | Privacy of individuals | Only what official or published sources state (for example court records). Removal route provided. | ✅ |
| Outages vs attacks | Wrongly implying an attack | Outages are never called attacks without an official source (data rules in CLAUDE.md). | ✅ |
| Not advice | Reliance on wrong information | "Information, not advice" in the terms, a disclaimer in every alert, and a no-warranty and limitation-of-liability clause. | ✅ |
| AI-generated content | Transparency | About explains that AI jobs do the research under published rules, and that mistakes are possible. | ✅ |
| Data source terms | Licence conditions | CISA KEV (public domain), FIRST EPSS, NVD (required "not endorsed" notice included), IODA and GDACS are attributed on About. | ✅ |
| Trademarks | Implying endorsement | Names are used only to identify vendors; stated in the terms. | ✅ |
| Third-party code | Licence notices | d3 and topojson (ISC), supabase-js (MIT) are credited on About and in the README. | ✅ |

## Accounts and personal information

| Law or practice | Requirement | Where | Status |
|---|---|---|---|
| PIPEDA (Canada), the 10 fair information principles | Accountability, purpose, consent, limiting collection, use and retention, accuracy, safeguards, openness, access, challenging compliance | Privacy policy. Data minimised (email, settings, opt-in terms, encrypted list). Self-service access, export and deletion. Privacy officer named. | ✅ (contact 🟡) |
| GDPR and UK GDPR (users in Europe) | Lawful basis per purpose, rights, international transfers, processors listed, 72-hour breach notification | Privacy policy table with bases. Processors listed with links. Supabase and Brevo DPAs cover transfers. Breach steps in docs/accounts.md. | ✅ (accept the processors' DPAs 🟡) |
| Quebec Law 25 | Person in charge of personal information, privacy by default | Maintainer named as privacy officer. Nothing shared or synced unless the user turns it on. | ✅ |
| CASL (Canada's anti-spam law) | Express consent, sender identification, mailing address, contact method, unsubscribe working within 10 business days, consent records | Unticked consent box. Consent wording, version and time stored. Every email names the sender, gives the mailing address and contact page, and has a one-click unsubscribe plus List-Unsubscribe headers. The job refuses to send without a mailing address. | ✅ (mailing address 🟡) |
| CAN-SPAM (US) and bulk-sender rules (Gmail, Yahoo) | Physical address, unsubscribe; SPF, DKIM and DMARC for the sending domain | Same as CASL. Authentication of the sender is done by Brevo for a verified sender. | ✅ / ⬜ own domain later |
| Children | Under-16s not targeted | Age confirmation at sign-up; stated in the policy. | ✅ |
| Cookies and ePrivacy | Consent for non-essential cookies or trackers | No cookies, analytics or ads. Local storage is used only for user-requested features and sign-in. Explained in the policy, so no banner is needed. | ✅ |
| Security safeguards | Appropriate to sensitivity | RLS tested in CI, end-to-end encrypted sync, strict CSP, pinned libraries, security.txt and a disclosure policy. | ✅ |
| Vulnerability disclosure | A way to report | security.txt (RFC 9116) and About → Security disclosure. Private reporting must be switched on in GitHub. | 🟡 enable |
| Accessibility (AODA in Ontario; WCAG 2.2 AA) | AODA obliges organisations; a one-person project is outside its scope, but we aim for WCAG 2.2 AA | Accessibility statement on About; keyboard support; shapes plus a colour-blind-safe palette; reduced motion respected. | ✅ |
| Records | Consent records, breach log | Consent stored per account. Keep a private breach log, even of breaches not reported. | ✅ / 🟡 log if needed |

## Owner to-do before accounts go live

1. Set a dedicated `contact_email` in `config/site.json` (for example a free address made just for CyberView).
2. Set a `mailing_address` (a PO box or virtual mailbox keeps your home address private).
3. Turn on GitHub private vulnerability reporting.
4. Accept Supabase's and Brevo's data processing agreements in their dashboards.
5. Have a lawyer review `legal/privacy.html` and `legal/terms.html`.
6. Optional later: a domain of your own (better email deliverability, and real HTTP security headers if hosting moves to Cloudflare).
