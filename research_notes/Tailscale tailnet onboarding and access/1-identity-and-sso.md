# Tailscale Identity and Enterprise Sign-On for a Tailnet (SSO & User-Provisioning Layer)

*Research scope: how users authenticate, get provisioned, and are represented. NOT device-join mechanics and NOT ACL syntax (separate researchers), though connection points are flagged. Current as of 2026-11-01. Facts are date-stamped with each source page's "Last validated" date where available. **[TRUST MODEL]** tags mark facts bearing on what Tailscale's control plane / identity layer must see or store about users — included because this research informs recURd (a ciphertext-only coordination network); these are documented Tailscale facts only, not recURd design.*

> **Terminology / plan-name caveat up front:** The assignment lists plans as "Personal/Free, Starter, Premium, Enterprise." As of the pages read (© 2026), Tailscale's current tiers are **Personal (free), Standard ($8/user/mo), Premium ($18/user/mo), Enterprise (custom quote)**. "Starter" is a *legacy* plan name; the `user-roles` and `pricing` pages both use "Standard" as the entry paid tier. A third-party source dates a plan restructure to 8 April 2026 (lower confidence). Legacy Starter/Team/Premium plans are retained "for at least the first year." See §1 plan-gating sub-section.

---

## Q1. SSO identity providers, setup flow, and plan gating (incl. SAML, custom OIDC)

### Takeaway
Tailscale has **no passwords and no email sign-up**; all authentication is delegated to an external identity provider over **OpenID Connect (OIDC) — SAML is not supported**. It natively supports Apple, Google (incl. Workspace), GitHub, Microsoft (incl. Entra ID), Okta, and OneLogin, plus any custom OIDC provider. Only a tailnet **Owner** can set up or switch the identity provider. Native SSO appears available on all plans (it is mandatory, since there are no passwords).

### Cited Findings
- **Native providers:** Apple, Google (covers Gmail and Google Workspace / G Suite), GitHub, Microsoft (covers Microsoft Accounts, Office365, Active Directory, and Microsoft Entra ID), Okta, and OneLogin — [Supported SSO identity providers, last validated Jan 5 2026](https://tailscale.com/kb/1013/sso).
- **The page uses "Microsoft Entra ID" and does not say "Azure AD" by name** (Azure AD is the former name of Entra ID) — [kb/1013/sso](https://tailscale.com/kb/1013/sso).
- **SAML is not supported.** The SSO page and the custom-OIDC page refer only to OpenID Connect; neither mentions SAML. Okta/Entra/OneLogin integrate via OIDC, not SAML — [kb/1013/sso](https://tailscale.com/kb/1013/sso); [Custom OIDC, last validated Dec 10 2025](https://tailscale.com/kb/1240/sso-custom-oidc).
- **No passwords, no email sign-up.** "Tailscale has no passwords and doesn't support email sign-up." Tailscale does not handle authentication itself — [kb/1013/sso](https://tailscale.com/kb/1013/sso). **[TRUST MODEL]** The control plane (`login.tailscale.com`) is purely an OIDC relying party; it never sees user passwords and brokers identity entirely through the external IdP.
- **Who can configure:** "You need to be an Owner of a tailnet to set up an identity provider." Switching providers is done via a separate "Switch identity provider" page — [kb/1013/sso](https://tailscale.com/kb/1013/sso).
- **Data Tailscale requests/stores:** Tailscale requests users' **email and name**; for some providers it stores a **photo URL but not the photo** — [kb/1013/sso](https://tailscale.com/kb/1013/sso). **[TRUST MODEL]** The control plane stores per-user PII: email, display name, and (for some IdPs) a profile-photo URL.
- **GitHub specifics:** Tailscale requests the minimum permissions needed to read team membership; the OAuth grant includes access to repositories and project boards, but Tailscale states it does not use their content — [kb/1013/sso](https://tailscale.com/kb/1013/sso).
- **Custom OIDC — requirements:** signing algorithm **ES256 or RSA (RSA ≥ 2048-bit)**; scopes `openid`, `profile`, `email`; **domain ownership proven via a WebFinger endpoint**; callback/redirect URL `https://login.tailscale.com/a/oauth_response` must be registered with the IdP; self-hosted providers must be reachable on the public internet; **JWE (encrypted) access tokens are not supported for `id_tokens`** — [kb/1240/sso-custom-oidc, last validated Dec 10 2025](https://tailscale.com/kb/1240/sso-custom-oidc).
- **WebFinger detail:** served at `https://${domain}/.well-known/webfinger`; the JRD must include a link with rel `http://openid.net/specs/connect/1.0/issuer` pointing to the issuer URL; the issuer must exactly match `/.well-known/openid-configuration`; Tailscale reads the issuer from WebFinger only during initial setup — [kb/1240/sso-custom-oidc](https://tailscale.com/kb/1240/sso-custom-oidc). **[TRUST MODEL]** The control plane maps domain → issuer → user; domain ownership is asserted via WebFinger at setup.
- **Custom OIDC — admin console setup flow:** Sign up with OIDC page → enter administrator's full email (its domain must match the WebFinger domain) → **Get OIDC Issuer** → enter **Client ID + Client secret** → optionally choose prompts (`none`, `consent` [default], `login`, `select_account`) → **Sign up with OIDC** → authenticate with the setup email. The person who configures OIDC at initial tailnet creation becomes the first user and the **Owner** — [kb/1240/sso-custom-oidc](https://tailscale.com/kb/1240/sso-custom-oidc).
- **Custom OIDC — providers needing no extra config:** Auth0, AWS Cognito, Dex, ZITADEL (Cloud and OSS), plus Codeberg, Duo, Gitea, Keycloak, Ory, Ping Identity, Pocket ID. **Special steps:** Authelia, Authentik, FoxIDs (own guides); GitLab (needs active browser session); JumpCloud (attribute mapping + Client Secret Basic); Zoho (Server-based Applications client type, data-center-matched issuer) — [kb/1240/sso-custom-oidc](https://tailscale.com/kb/1240/sso-custom-oidc).
- **One provider per domain (hard rule):** "All users connecting from the same domain must use the same identity provider." — [kb/1240/sso-custom-oidc](https://tailscale.com/kb/1240/sso-custom-oidc).
- **Migration limits:** Only custom-domain accounts can migrate to custom OIDC; public domains like `gmail.com` cannot. **GitHub and Apple tailnets cannot be migrated to or from.** — [kb/1013/sso](https://tailscale.com/kb/1013/sso); [kb/1240/sso-custom-oidc](https://tailscale.com/kb/1240/sso-custom-oidc).
- **Passkeys/MFA:** "Passkeys are supported for any tailnet you're authorized to join." MFA is turned on in the SSO provider and applies to Tailscale — [kb/1013/sso](https://tailscale.com/kb/1013/sso). (More in Q6.)
- **PKCE:** An earlier search summary (kb/1240 variant) reported "Tailscale doesn't support PKCE... disable it if your provider enables it by default." The *currently fetched* kb/1240/sso-custom-oidc page does **not** mention PKCE — treat as possibly-removed/changed; verify before relying — [search-reported, kb/1240](https://tailscale.com/kb/1240/sso-custom-oidc).

### Plan gating (cross-cutting sub-section)
- **Current tiers (© 2026 pricing page):** Personal $0 (up to 6 users, unlimited user devices); **Standard $8/user/mo** (unlimited users); **Premium $18/user/mo**; **Enterprise custom** — [Pricing](https://tailscale.com/pricing).
- **Native SSO:** Not mapped to a tier on any page; because Tailscale is passwordless and SSO is mandatory, native SSO (Google/Microsoft/GitHub/Apple/Okta/OneLogin) is effectively **all plans incl. free**. "SSO with any IdP" appears in the pricing feature-comparison table but the per-plan checkmarks did not render in fetch — [Pricing](https://tailscale.com/pricing). (See Gaps.)
- **Advanced user roles** (Network admin, IT admin, Billing admin, Auditor): **Standard, Premium, Enterprise** — [user-roles, last validated Dec 4 2025](https://tailscale.com/docs/reference/user-roles); pricing: "Advanced user roles for billing, IT, auditors, and more" listed under Standard — [Pricing](https://tailscale.com/pricing).
- **SCIM user & group provisioning:** **Standard, Premium, Enterprise** (NOT Personal/free) — [user-group-provisioning](https://tailscale.com/kb/1290/user-group-provisioning); pricing lists "Deploy users and groups with SCIM" under Standard — [Pricing](https://tailscale.com/pricing).
- **ACL group limits scale by plan:** Personal up to 3 ACL groups, Standard up to 10, Premium up to 300, Enterprise custom (enforcement "not active yet," to roll out "over the next few months") — [Pricing](https://tailscale.com/pricing). (ACL-researcher connection.)
- **Config audit logs:** all plans. **Log streaming / network flow logs:** Premium and above — [Pricing](https://tailscale.com/pricing). (See Q7.)
- **Enterprise-named identity items:** custom tailnet subdomains, custom MSA, pay-by-invoice — [Pricing](https://tailscale.com/pricing).
- **Custom-domain tailnets start with a 14-day Enterprise trial** (all features, no user/device/usage limits) — [Pricing](https://tailscale.com/pricing).

### Inferences
- Because every Tailscale account authenticates through an external OIDC IdP, the Tailscale control plane is architecturally an OIDC relying party / identity broker — it must know each user's IdP, issuer, email, and name to function, but is not the credential store.
- "SSO with any IdP" (custom OIDC) is almost certainly available broadly (historically all plans), but I could not confirm its exact per-plan gating from the fetched pages.

### Gaps
- Exact per-plan checkmarks for "SSO with any IdP" / custom OIDC did not render from the pricing page; could not confirm whether custom OIDC is gated to a paid tier.
- Current PKCE support status is ambiguous (search summary vs. fetched page conflict).
- Per-provider native setup steps (Google, Entra, Okta, OneLogin, Apple individual pages) were not each fetched; the SSO hub links to them.

---

## Q2. SCIM user & group provisioning

### Takeaway
SCIM provisioning is a **Standard/Premium/Enterprise** feature supporting **three native IdPs — Google Workspace, Microsoft Entra ID, and Okta** — plus a **custom SCIM API (alpha)** for others. It syncs **users and group memberships** (not roles); synced groups become ACL `group:` references of the form `group:name@domain`. A central caveat: **you cannot run SCIM provisioning and user approval on the same tailnet**, and **suspending a user in the IdP does not immediately cut their access** (keys persist until expiry) unless you disable the user.

### Cited Findings
- **Supported native IdPs (3):** Google Workspace, Microsoft Entra ID, Okta — [user-group-provisioning, last validated Dec 8 2025](https://tailscale.com/kb/1290/user-group-provisioning). (Google Workspace SCIM is a newer addition vs. the older Okta/Entra-only set.)
- **Plan:** Standard, Premium, Enterprise — [user-group-provisioning](https://tailscale.com/kb/1290/user-group-provisioning); [Okta SCIM, last validated Jan 5 2026](https://tailscale.com/kb/1180/sso-okta-scim); [Entra SCIM, last validated Jul 6 2026](https://tailscale.com/kb/1249/sso-azure-ad-scim).
- **What syncs:** users (create, update attributes, suspend) and **group membership** from the IdP to Tailscale — [user-group-provisioning](https://tailscale.com/kb/1290/user-group-provisioning). **[TRUST MODEL]** The control plane ingests and stores the org's user directory and group-membership graph from the IdP.
- **Groups → ACLs:** reference synced groups in the policy file as `group:name@domain`, e.g. `group:security-team@example.com`, usable in `grants`/`tagOwners`; they appear under "Group Sync" on the Access controls page — [user-group-provisioning](https://tailscale.com/kb/1290/user-group-provisioning); [Okta SCIM](https://tailscale.com/kb/1180/sso-okta-scim). (ACL-researcher connection: the `@domain` suffix is appended by Tailscale; it is not part of the IdP group name.)
- **Entra also supports reference by group ID** (`externalGroupId`): e.g. `group:3ac067a2-...@example.com`; referencing by ID survives renames, whereas referencing by name **fails closed** on rename (error shown) — [Entra SCIM](https://tailscale.com/kb/1249/sso-azure-ad-scim). Okta name-rename also fails closed — [Okta SCIM](https://tailscale.com/kb/1180/sso-okta-scim).
- **Deprovisioning by provider:**
  - **Okta:** deactivating or unassigning from the Tailscale app → suspends in Tailscale. **Suspending in Okta does nothing** (not synced). Deletions can't be synced — [Okta SCIM](https://tailscale.com/kb/1180/sso-okta-scim).
  - **Entra ID:** disable → suspend; delete → soft-delete (suspend), then hard-delete ≈30 days later → deleted in Tailscale. Sync interval is **every 40 minutes (not configurable)**; on-demand provisioning can sync a single user (e.g. offboarding) in under 30 seconds — [Entra SCIM](https://tailscale.com/kb/1249/sso-azure-ad-scim).
  - **Google Workspace:** suspending or deleting a user → suspends in Tailscale; a recreated user is treated as new — [user-group-provisioning](https://tailscale.com/kb/1290/user-group-provisioning).
- **Critical offboarding caveat:** "A suspended user stays logged in and keeps their node access and policy-granted permissions until device keys expire and they can't reauthenticate." To cut access immediately, **disable the user in the IdP** — [user-group-provisioning](https://tailscale.com/kb/1290/user-group-provisioning); [Okta SCIM](https://tailscale.com/kb/1180/sso-okta-scim). **[TRUST MODEL]** Access revocation is not instantaneous; it is bounded by device key expiry.
- **Group-name limitations:** names are **parsed lowercase** (IdP casing ignored); **names cannot contain `@`** (both Okta and Entra); Okta names may include spaces — [Okta SCIM](https://tailscale.com/kb/1180/sso-okta-scim); [Entra SCIM](https://tailscale.com/kb/1249/sso-azure-ad-scim).
- **Nested groups (Entra):** members of nested subgroups included **up to 5 levels deep**; beyond that excluded — [Entra SCIM](https://tailscale.com/kb/1249/sso-azure-ad-scim).
- **Pushed groups don't overwrite policy-file groups:** you can use both IdP-synced groups and groups defined in the tailnet policy file — [Okta SCIM](https://tailscale.com/kb/1180/sso-okta-scim); [user-group-provisioning](https://tailscale.com/kb/1290/user-group-provisioning).
- **Synced groups CANNOT assign user roles / admins** — only ACL permissions — [user-group-provisioning](https://tailscale.com/kb/1290/user-group-provisioning); [Okta SCIM](https://tailscale.com/kb/1180/sso-okta-scim); [Entra SCIM](https://tailscale.com/kb/1249/sso-azure-ad-scim); [user-roles](https://tailscale.com/docs/reference/user-roles).
- **SSO vs SCIM app topology:** if the same IdP app does both SSO and SCIM, only users assigned to that app can sign up; with separate apps, Tailscale recommends enabling user approval — [user-group-provisioning](https://tailscale.com/kb/1290/user-group-provisioning).
- **Entra attributes:** supported SCIM attributes are `externalId`, `userName` (must match sign-in email), `emails`, name fields, `displayName`, `active`, `preferredLanguage`; `photos` populated at login not synced; **Enterprise User Schema Extension attributes are NOT supported** (request fails if included) — [Entra SCIM](https://tailscale.com/kb/1249/sso-azure-ad-scim).
- **Custom SCIM API (alpha):** base URL `https://api.tailscale.com/scim/v2`; endpoints `/Users` and `/Groups` (GET list w/ `filter`+`attributes`, POST create, PATCH update incl. member add/remove, DELETE); for IdPs without native SCIM; auth via a **SCIM API key** (bearer token) generated in admin console → User management → User & Group Provisioning → Enable Provisioning; if `externalId` is set it must equal the user's OIDC `sub` (ties to custom OIDC); "Custom SCIM is currently in alpha." Last validated Jan 5 2026 — [Custom SCIM](https://tailscale.com/docs/integrations/identity/custom-scim). **[TRUST MODEL]** A long-lived SCIM bearer key held by the IdP can create/suspend users and mutate groups in the control plane.
- **Manual deletion:** you can delete unsynced users, suspended synced users, and users from other domains; you **cannot** delete actively-synced users (they get recreated next sync) — [user-group-provisioning](https://tailscale.com/kb/1290/user-group-provisioning).

### Inferences
- The control plane is the authoritative store for group→member resolution used by ACLs; it must hold the full membership graph (incl. nested expansion up to the 5-level cap for Entra) to evaluate policy.
- Because suspension in the IdP is not always synced (Okta "suspend" is a no-op) and revocation waits on key expiry, immediate offboarding is operationally fragile — a repeatedly-cited gotcha.

### Gaps
- Did not fetch the Google Workspace SCIM provider page specifically (details beyond "suspend/delete → suspend; recreated user is new" not captured).
- Custom SCIM page does not state a required plan explicitly.
- Whether custom-OIDC tailnets can use the custom SCIM API in practice (both reference each other, but exact eligibility/combinations not fully documented).

---

## Q3. User roles and permissions

### Takeaway
Seven IAM roles govern **admin-console access only** (separate from ACLs, which govern device-to-device traffic). **Owner, Admin, Member** are "basic" (all plans). **Network admin, IT admin, Billing admin, Auditor** are "advanced" (Standard/Premium/Enterprise). Exactly one Owner; users cannot change their own role (except an Owner transferring ownership); roles cannot be assigned via SCIM groups.

### Cited Findings
- **Roles govern admin-console access, not traffic:** "User roles are IAM roles that restrict admin console access." Device access is governed by the policy file (ACLs) — [user-roles, last validated Dec 4 2025](https://tailscale.com/docs/reference/user-roles).
- **Basic roles (all plans):**
  - **Owner** — holds the account, sees everything incl. plan/billing; exactly one — [user-roles](https://tailscale.com/docs/reference/user-roles).
  - **Admin** — can do anything in the admin console incl. plan/billing; multiple allowed — [user-roles](https://tailscale.com/docs/reference/user-roles).
  - **Member** — **cannot access the admin console**; connects to nodes per ACLs; **new users default to Member** — [user-roles](https://tailscale.com/docs/reference/user-roles).
- **Advanced roles (Standard/Premium/Enterprise):**
  - **Network admin** — manages network config (policy file, DNS, subnets); read-only on users/devices/general settings; no plan/billing access — [user-roles](https://tailscale.com/docs/reference/user-roles).
  - **IT admin** — manages users and machines, can change some general settings; read-only on network info; cannot accept subnet-router routes; no plan/billing — [user-roles](https://tailscale.com/docs/reference/user-roles). *(Note: an older KB framing described IT admin as "users and machines only"; the current `/docs/reference/user-roles` matrix is authoritative — see matrix below.)*
  - **Billing admin** — manages plan and billing only; read-only elsewhere; does **not** automatically receive billing emails — [user-roles](https://tailscale.com/docs/reference/user-roles).
  - **Auditor** — can **read all** tailnet configurations, change nothing — [user-roles](https://tailscale.com/docs/reference/user-roles).
- **Permission matrix** (✅=yes; Own=Owner, Adm=Admin, Net=Network admin, IT=IT admin, Bill=Billing admin, Aud=Auditor, Mem=Member) — [user-roles](https://tailscale.com/docs/reference/user-roles):

| Permission | Own | Adm | Net | IT | Bill | Aud | Mem |
|---|---|---|---|---|---|---|---|
| Access admin console | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| Read / Write policy file | ✅/✅ | ✅/✅ | ✅/✅ | ✅/❌ | ✅/❌ | ✅/❌ | ❌/❌ |
| Read / Write network config | ✅/✅ | ✅/✅ | ✅/✅ | ✅/❌ | ✅/❌ | ✅/❌ | ❌/❌ |
| Read / Write feature config | ✅/✅ | ✅/✅ | ✅/❌ | ✅/✅ | ✅/❌ | ✅/❌ | ❌/❌ |
| Configure user & group provisioning (SCIM) | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Read / Write machines | ✅/✅ | ✅/✅ | ✅/❌ | ✅/✅ | ✅/❌ | ✅/❌ | ❌/❌ |
| Read / Write users and roles | ✅/✅ | ✅/✅ | ✅/❌ | ✅/✅ | ✅/❌ | ✅/❌ | ❌/❌ |
| Generate auth keys | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| Generate API tokens & OAuth clients | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| Share / Accept a shared node | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Use any tag without being tag owner | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| Read configuration audit logs | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| Use Tailscale SSH Console (if policy allows) | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| Write webhooks | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| Write tailnet name | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| Read / Write payment plan; Write billing info | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ |

- **Ownership rules:** exactly one Owner; Owner can transfer ownership on the Users page; an Owner account can't be deleted until ownership is transferred; **users cannot change their own role** (only exception: Owner transferring the Owner role); lost Owner access → contact support — [user-roles](https://tailscale.com/docs/reference/user-roles).
- **Roles are set on the Users page, not via SCIM.** Owner/Admin/IT admin can configure user & group provisioning, but synced groups cannot assign roles — [user-roles](https://tailscale.com/docs/reference/user-roles).
- **Policy-file (not role) controlled:** machine access, tag ownership (tagOwners), and route/exit-node auto-approval — [user-roles](https://tailscale.com/docs/reference/user-roles). (Connection to ACL + device-join researchers.)

### Inferences
- Role design enforces separation of duties (e.g., Network admin writes policy but can't touch users/billing; Billing admin touches only billing). Note the IT admin can write users/roles — effectively it can grant roles, a privilege-escalation surface to flag.
- "Read configuration audit logs" is granted to every admin-console role (all except Member), aligning with the Auditor's read-everything posture.

### Gaps
- The `/docs/reference/user-roles` page does not itself restate which plans unlock advanced roles; the Standard/Premium/Enterprise gating comes from the role categorization + pricing page.

---

## Q4. Domain claiming/verification, multi-domain tailnets, user approval, invited vs SSO-provisioned

### Takeaway
A tailnet's **primary domain** is set by the creator's email domain. Additional domains are added by **verifying ownership (DNS TXT challenge)** then setting the verified domain as a **domain alias** (Owner/Admin; custom-domain tailnets only — not gmail.com, not GitHub-IdP tailnets). **User approval** (all plans, **on by default for tailnets created on/after 22 May 2025**) holds every new user as "needs approval" until an Owner/Admin/IT admin approves — this applies to **both invited and SSO-provisioned sign-ups**, but **cannot coexist with SCIM provisioning**.

### Cited Findings
- **Primary domain:** the creator's email domain becomes the tailnet's primary domain (e.g. `bob@example.com` → `example.com`) — [Domain aliases, last validated May 11 2026](https://tailscale.com/docs/account/domain-aliases).
- **Domain verification flow:** Owner/Admin → Domains page → **Add domain** → Tailscale issues a **TXT record** to place at a `_tailscale-challenge` subdomain; domain stays **Pending** until detected; propagation up to a few hours; leave the TXT record in place (Tailscale keeps checking) — [Domain verification](https://tailscale.com/docs/account/domain-verification). **[TRUST MODEL]** Domain ownership is asserted to the control plane via DNS TXT (and via WebFinger for custom OIDC, Q1).
- **Multi-domain via alias:** after verification, open the verified domain's menu → **Set as domain alias** → confirm; users under the aliased domain can then sign in to the tailnet. Requires **Owner or Admin** — [Domain aliases](https://tailscale.com/docs/account/domain-aliases).
- **Alias limits:** only for **custom-domain** tailnets — **shared-domain tailnets (e.g. `@gmail.com`) cannot** set aliases; **GitHub-IdP tailnets cannot** use aliases; once an alias exists, outside-org tailnets can't use that domain to authenticate; legacy support-created aliases show a "Legacy" label — [Domain aliases](https://tailscale.com/docs/account/domain-aliases).
- **Removing an alias:** Owner/Admin can remove; optionally delete users under that domain; if kept, existing users can still sign in but **new** users under the formerly-aliased domain cannot; type-to-confirm — [Domain aliases](https://tailscale.com/docs/account/domain-aliases).
- **User approval — mechanism:** when enabled, a new user is set to **"needs approval"** on first login; while unapproved they "can connect to the coordination server but cannot connect to other devices in the tailnet." After approval, immediate access. Removing an unapproved user does **not** stop them re-logging in (returns them to unapproved) — [User approval, last validated Sep 25 2025](https://tailscale.com/kb/1239/user-approval). **[TRUST MODEL]** Even unapproved users reach/register with the coordination server; approval gates peer connectivity, not control-plane registration.
- **User approval — roles:** enable/disable requires Owner/Admin/**Network admin**; approve/remove requires Owner/Admin/**IT admin**; an Admin can change an unapproved user's role before approving — [User approval](https://tailscale.com/kb/1239/user-approval).
- **User approval — where & plan:** toggle on the User management page (`/admin/settings/user-management`); review via "Needs approval" badge or `status:needsapproval` filter (Users page) and `disabled:user-needs-approval` on Machines; **available on all plans** — [User approval](https://tailscale.com/kb/1239/user-approval).
- **User approval — default:** **enabled by default for tailnets created on/after May 22 2025**; disabled by default for older tailnets — [User approval](https://tailscale.com/kb/1239/user-approval). (A separate search summary attributes the default change to a "May 2025 security incident" and says it was applied to all new tailnets — [Tailscale blog: invite/review users](https://tailscale.com/blog/invite-users); the KB page itself gives no reason.)
- **User approval ⇄ SCIM mutual exclusion:** "You can't enable both features on the same tailnet." Enabling provisioning while approval is on **disables** approval; any still-pending users must be approved/removed manually — [User approval](https://tailscale.com/kb/1239/user-approval); [user-group-provisioning](https://tailscale.com/kb/1290/user-group-provisioning).
- **Invited users under approval:** per search summary, if user approval is enabled, invited users must still be approved before joining; **unused invites expire after 30 days** — [Tailscale blog: invite/review users](https://tailscale.com/blog/invite-users); [Invite any user](https://tailscale.com/docs/features/sharing/how-to/invite-any-user). (Not restated on the user-approval KB page — medium confidence.)

### Inferences
- Invited vs SSO-provisioned users: both funnel through the same OIDC login and the same "needs approval" gate; the difference is the *entry path* (an explicit invite/share vs. self-service domain sign-up). SCIM-provisioned users bypass approval entirely (approval is disabled when SCIM is on), since the IdP app assignment is the gate.
- The "new users under a removed alias can't sign in, existing ones can" behavior implies the control plane persists per-user domain eligibility independent of current alias state.

### Gaps
- The user-approval KB page does not itself detail invited-vs-SSO differences or invite expiry; those come from blog/how-to sources (medium confidence, not fetched in full).
- Did not fetch `domain-ownership`/`domain-verification` pages in full (relied on domain-aliases fetch + search snippet for verification steps).
- No explicit statement of which plan (if any) gates domain aliases / multi-domain (custom tailnet subdomains are Enterprise, but basic aliasing on a custom domain appears unrestricted — unconfirmed).

---

## Q5. How user identity is represented and used downstream (login name, `user:`/`group:`, `autogroup:member`, identity-based device tagging)

### Takeaway
A user is identified by an **email-style login name** (`loginName`, e.g. `amelie@example.com`; for GitHub IdP it is the GitHub username). Identity flows into policy as `user:<loginName>` (grants/ACL src/dst) and groups as `group:name@domain`; `autogroup:member` denotes any (non-tagged) tailnet member. Devices authenticate **either as a user** (bound to that identity, subject to key expiry) **or with a tag** (owned by the tailnet, key expiry disabled) — the latter deliberately detaches the device from a human identity. *(Exact policy syntax is the ACL researcher's scope; captured here only as identity representation.)*

### Cited Findings
- **Login name = email-style identifier.** The audit-log API returns `loginName` described as "email or GitHub username" plus `displayName` — [Configuration audit logging, last validated Jan 5 2026](https://tailscale.com/kb/1203/audit-logging). The group-visibility CLI example shows `LoginName` in email form `amelie@example.com` — [Group visibility on clients, last validated Jun 10 2026](https://tailscale.com/docs/features/group-visibility-clients). A third-party schema also describes `login_name` as email-style — [Cartography Tailscale schema](https://cartography-cncf.github.io/cartography/modules/tailscale/schema.html).
- **`group:` references:** synced/policy groups are referenced `group:name@domain` (Entra also `group:<externalGroupId>@domain`) — [user-group-provisioning](https://tailscale.com/kb/1290/user-group-provisioning); [Entra SCIM](https://tailscale.com/kb/1249/sso-azure-ad-scim). (See Q2.)
- **`autogroup:member`:** used as a policy `src` to mean "any tailnet member can reach a service"; appears in SSH rules (`autogroup:member` → `autogroup:self`) — [GitHub issue #15128](https://github.com/tailscale/tailscale/issues/15128); [Visual policy editor reference](https://tailscale.com/docs/reference/visual-editor). (Authoritative definition is in ACL-syntax docs — ACL-researcher scope.)
- **Identity info the control plane distributes to devices — DEFAULT ON:** "the Tailscale control plane sends... user name, user login, and user profile picture [URL]" to a device **if the user has access to that device** — [Group visibility on clients](https://tailscale.com/docs/features/group-visibility-clients). **[TRUST MODEL]** By default the coordination server propagates each user's name, login, and profile-picture URL to peer devices the user can reach — identity metadata leaves the control plane and lands on clients in cleartext.
- **Group membership distribution — DEFAULT OFF (opt-in):** "By default, the Tailscale control plane does not send group membership information to devices." Enable per-target via a `nodeAttrs` entry granting app capability `tailscale.com/visible-groups` (a.k.a. `node-attr-visible-groups`); `groups` may be `"*"` or specific (policy-file or SCIM-synced) groups; readable via `tailscale status --json` (`Groups`), `tsnet`, LocalAPI; requires client **v1.97.8+**; feature is **alpha** — [Group visibility on clients](https://tailscale.com/docs/features/group-visibility-clients). **[TRUST MODEL]** Group membership can be exposed to clients but only when an admin opts in.
- **Identity-based device tagging / user-vs-tag:** tagged devices have **key expiry disabled by default** when a tag is first applied and the device authenticates — [key expiry, last validated Jan 5 2026](https://tailscale.com/kb/1028/key-expiry). The role permission "Use any tag without being tag owner" distinguishes tag authority (Owner/Admin/Network admin) — [user-roles](https://tailscale.com/docs/reference/user-roles). (Tag ownership via `tagOwners` is policy-file controlled — ACL + device-join researchers.)

### Inferences
- Email (login name) is effectively the primary key for a user across SSO, policy (`user:`), audit logs, and SCIM (`userName` must equal sign-in email). **[TRUST MODEL]** The control plane must store and index the plaintext email/login for every user to resolve policy and attribute actions.
- Tagging a device is the documented way to decouple a node from a human identity (no per-user key expiry, owned by the tailnet) — relevant to how "machine"/agent identities differ from user identities.

### Gaps
- Did not fetch the authoritative ACL/grants syntax page for the exact `user:`/`autogroup:member` grammar (intentionally the ACL researcher's topic); representation facts above are cross-sourced but the canonical definition page was not read.
- `autogroup:member`'s precise definition (members vs. shared users vs. tagged nodes) taken from usage examples + general docs, not a single definitional quote.

---

## Q6. MFA/WebAuthn, session/key expiry tied to identity, SSO-driven re-authentication

### Takeaway
Tailscale **delegates MFA entirely to the IdP** (it has no passwords); **passkeys** are supported for authorized tailnets. Device trust is time-boxed by **key expiry** (default 180 days for new domains, settable 1–180, disablable per-device; tagged devices default to no expiry). The admin-console **browser session lasts 30 days** and is explicitly unrelated to key expiry; "Custom authentication periods" and "Custom admin console session timers" exist as (likely higher-tier) controls.

### Cited Findings
- **MFA is enforced at the IdP:** "MFA is turned on in your SSO provider and applies to Tailscale." Tailscale doesn't handle authentication itself — [kb/1013/sso](https://tailscale.com/kb/1013/sso). **[TRUST MODEL]** Tailscale never sees MFA factors or credentials; it trusts the IdP's authenticated OIDC assertion.
- **Passkeys/WebAuthn:** "Passkeys are supported for any tailnet you're authorized to join." — [kb/1013/sso](https://tailscale.com/kb/1013/sso). (No separate Tailscale-native MFA beyond passkeys; depth not documented on this page.)
- **Key expiry defaults/range:** new domains default to **180 days**; custom authentication period settable **1–180 days** in Device management → Key Expiry; changes apply to devices that log in *after* the change; a renewed key gets "standard expiry (6 months by default)" (page's own slight 180-day vs "6 months" wording mismatch) — [key expiry, last validated Jan 5 2026](https://tailscale.com/kb/1028/key-expiry).
- **Disabling expiry:** per-device from the Machines page; recommended for trusted servers/subnet routers/IoT; **tagged devices have key expiry disabled by default** — [key expiry](https://tailscale.com/kb/1028/key-expiry).
- **Expiry recovery:** admins can "Temporarily extend key" → 30-minute window to reauthenticate or disable expiry; `tailscale up --force-reauth` forces device reauth; "Reauthorize machine" option for user-owned machines mid-reauth — [key expiry](https://tailscale.com/kb/1028/key-expiry).
- **Who controls:** Network admins control per-device expiry, the custom period, and temporary extensions; device owners renew via CLI — [key expiry](https://tailscale.com/kb/1028/key-expiry).
- **Admin-console session:** the admin-console browser session lasts **30 days** and is explicitly **unrelated to key expiry**; a separate "Admin console session timeout" (idle) feature exists — [key expiry](https://tailscale.com/kb/1028/key-expiry); [manage-users hub, last validated Sep 30 2025](https://tailscale.com/docs/manage-users).
- **Custom session/auth controls on pricing:** "Custom authentication periods" and "Custom admin console session timers" are listed as features (no plan assignment rendered) — [Pricing](https://tailscale.com/pricing).
- **Plan gating:** enabling/disabling key expiry and setting a custom authentication period are **available on all plans** — [key expiry](https://tailscale.com/kb/1028/key-expiry).
- **Offboarding tie-in (from Q2):** a suspended IdP user keeps access "until device keys expire and they can't reauthenticate" — i.e., re-auth after expiry does route back through the IdP, which is how suspension eventually bites — [user-group-provisioning](https://tailscale.com/kb/1290/user-group-provisioning). **[TRUST MODEL]** The IdP is re-consulted at key-expiry/reauth, so IdP-side suspension is the ultimate (but delayed) kill switch.

### Inferences
- Key expiry is Tailscale's SSO-driven re-authentication mechanism: when a device key expires the user must re-run the login flow, which re-hits the IdP (and thus re-checks suspension/MFA). The key-expiry page describes reauth at the device/CLI level without naming the IdP, but the offboarding docs confirm the IdP is re-consulted.
- "Custom authentication periods" (how often users must re-auth) is likely the enterprise-grade generalization of key expiry; exact plan gating unconfirmed.

### Gaps
- The key-expiry page does **not** explicitly state that key expiry forces an *IdP* re-login (only device-level reauth); the IdP linkage is inferred from the offboarding docs — flag as not-fully-explicit.
- Depth of Tailscale's passkey/WebAuthn support (enrollment, enforcement, whether it can substitute for IdP MFA) not documented on pages read.
- Plan gating for "Custom authentication periods" / "Custom admin console session timers" not confirmed.

---

## Q7. Audit / visibility of user sign-on events

### Takeaway
**Configuration audit logs** (all plans, always on, cannot be disabled, **90-day** retention) **do** record several sign-in events — admin-console login/logout, web-interface login/logout, and node login/re-auth — each stamped with the **actor's identity** (name, email/GitHub username, internal ID). **Failed login attempts are NOT recorded** (you need the IdP's logs), and read-only activity is excluded.

### Cited Findings
- **Sign-in events ARE logged:** "Log in to admin console"/"Log out of admin console"; "Log in using web interface"/"Log out using web interface" (member users); "Log in node" (user logs in to / re-authenticates on a node) — [Configuration audit logging, last validated Jan 5 2026](https://tailscale.com/kb/1203/audit-logging). **[TRUST MODEL]** The control plane records who logged in, to what, and when, tied to identity.
- **Failed logins excluded:** "failed login attempts are not included in Tailscale events" — use the IdP's logs — [audit-logging](https://tailscale.com/kb/1203/audit-logging). **[TRUST MODEL]** Authentication failures are visible only to the IdP, not the Tailscale control plane.
- **Read-only actions excluded** (e.g., viewing the admin console) — [audit-logging](https://tailscale.com/kb/1203/audit-logging).
- **Log entry fields:** timestamp (`eventTime`), action, **actor**, target, and a diff (full diff incl. comments for policy-file changes). Actor for users shows name; API returns `loginName` (email or GitHub username) + `displayName` + an internal ID + type (e.g. `USER`); service-initiated events show the Tailscale service as actor — [audit-logging](https://tailscale.com/kb/1203/audit-logging). **[TRUST MODEL]** Each log row binds an action to a user's plaintext identity.
- **Not logged:** Support-initiated changes (incl. **identity-provider changes**, tailnet ID, billing, tailnet/user deletion); suspension of a user's nodes/API tokens/auth keys; deletion of a user's API tokens/auth keys; data-plane/network-flow info (that's network flow logs) — [audit-logging](https://tailscale.com/kb/1203/audit-logging).
- **Availability/retention:** available on **all plans**; "always enabled for all tailnets and cannot be disabled"; most recent **90 days**, not configurable — [audit-logging](https://tailscale.com/kb/1203/audit-logging); [Pricing: "All plans get access to Webhooks and Configuration audit logs!"](https://tailscale.com/pricing).
- **Access:** admin console **Logs page** (all admin-console roles; filter by timeframe/action/actor, newest first); API `/api/v2/tailnet/{tailnet_id}/logging/configuration` requiring token scope `logs:configuration:read` (RFC3339 `start`/`end`, no pagination); can stream to a SIEM — [audit-logging](https://tailscale.com/kb/1203/audit-logging). (Note: the page is ambiguous about whether "log streaming" delivers config audit logs vs. network flow logs — verify.)
- **Related, out-of-scope telemetry:** network flow logs (data-plane connections) and SSH session recording are separate features; log streaming / network flow logs are **Premium+** — [Pricing](https://tailscale.com/pricing).
- **Webhooks for user events:** a `userNeedsApproval` webhook can alert admins (e.g., to Slack) when a user needs approval — [search summary, user-approval](https://tailscale.com/kb/1239/user-approval). ("Write webhooks" is an admin-role permission — [user-roles](https://tailscale.com/docs/reference/user-roles).)

### Inferences
- For WHO-signed-on visibility, the config audit log is the primary in-product source but is coarse: it logs successful logins and re-auths with identity, not failures or session detail; comprehensive sign-on analytics (failed attempts, MFA challenges) must come from the IdP. **[TRUST MODEL]** The split means the control plane holds a durable 90-day identity-attributed record of successful sign-ons and config changes, while failure/credential telemetry stays at the IdP.

### Gaps
- Exact list of all logged sign-in action types may be longer than the examples quoted; full enumeration not captured.
- Ambiguity (per the page itself) over whether "log streaming" to SIEM carries configuration audit logs or only network flow logs — unresolved.

---

## Cross-cutting trust-model summary (what the Tailscale control plane must see/store about users)
*All items sourced above; consolidated here for the report-writer. Documented Tailscale facts only.*
- **Identity broker, not credential store:** passwordless; the control plane (`login.tailscale.com`) is an OIDC relying party; MFA/credentials live at the IdP — [kb/1013/sso](https://tailscale.com/kb/1013/sso). **It never sees passwords/MFA factors, but it does see the IdP's authenticated assertion and each user's email + name (+ photo URL for some IdPs).**
- **Durable PII at rest:** per-user email/login name, display name, photo URL; full group-membership graph via SCIM; roles — [kb/1013/sso](https://tailscale.com/kb/1013/sso); [user-group-provisioning](https://tailscale.com/kb/1290/user-group-provisioning).
- **Identity propagated to peers:** by default the control plane pushes user name, login, and profile-picture URL to devices the user can reach; group membership only if opted in — [group-visibility-clients](https://tailscale.com/docs/features/group-visibility-clients).
- **Durable identity-attributed activity log:** 90-day, non-disableable config audit log of successful logins/re-auths + config changes, each bound to a plaintext login name/ID — [audit-logging](https://tailscale.com/kb/1203/audit-logging).
- **Domain ownership asserted to control plane** via DNS TXT (`_tailscale-challenge`) and/or WebFinger (custom OIDC) — [domain-verification](https://tailscale.com/docs/account/domain-verification); [kb/1240/sso-custom-oidc](https://tailscale.com/kb/1240/sso-custom-oidc).
- **Long-lived SCIM bearer key** held by the IdP can mutate the control-plane user/group store — [custom-scim](https://tailscale.com/docs/integrations/identity/custom-scim).
- **Revocation is key-expiry-bounded**, not instant — [user-group-provisioning](https://tailscale.com/kb/1290/user-group-provisioning); [key-expiry](https://tailscale.com/kb/1028/key-expiry).
