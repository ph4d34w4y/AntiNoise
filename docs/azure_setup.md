# Azure setup

Everything here is optional: the app runs end to end on sample telemetry. Do this on day one so
live problems surface early, and capture live data well before the demo.

## 1. Know what your tenant can give you

| Source | Needs | Without it |
|---|---|---|
| Entra audit logs (`directoryAudits`) | Entra ID Free | — |
| Entra sign-in logs via API (`signIns`) | Entra ID P1 or P2 | HTTP 403, shown as a confidence limitation |
| Exchange mailbox audit (`MailItemsAccessed`, inbox rules) | M365 licence with auditing on; `MailItemsAccessed` has historically needed E5/Audit Premium | Scenario A still fires on consent + scopes, with lower confidence |
| OneDrive/SharePoint file audit | M365 licence with auditing on | Same as above |

A plain Azure subscription tenant is Entra ID Free: audit logs and every Graph response action work,
sign-in logs and M365 audit do not. A Microsoft Entra ID P2 or Microsoft 365 E5 trial on the test
tenant fills the gaps. Check current trial availability in the Microsoft 365 admin center.

## 2. Create two app registrations

Separate apps keep the blast radius small: the collector can only read, the responder can only do the
catalog actions.

**ctdip-collector** (application permissions, grant admin consent)

- Microsoft Graph: `AuditLog.Read.All`, `Directory.Read.All`
- Office 365 Management APIs: `ActivityFeed.Read` (only if collecting Exchange/OneDrive)

**ctdip-responder** (application permissions, grant admin consent)

- Microsoft Graph: `DelegatedPermissionGrant.ReadWrite.All`, `Application.ReadWrite.All`,
  `User.RevokeSessions.All`
- Azure RBAC for VM isolation (not Graph): `Network Contributor` and `Reader` on the demo resource group

```bash
az role assignment create --assignee <responder-app-client-id> --role "Network Contributor" \
  --scope /subscriptions/<sub>/resourceGroups/rg-ctdip-demo
az role assignment create --assignee <responder-app-client-id> --role "Reader" \
  --scope /subscriptions/<sub>/resourceGroups/rg-ctdip-demo
```

Create a client secret for each, put the values in `.env`, and never commit it.
`Application.ReadWrite.All` is powerful; use a throwaway test tenant, not a production one.

## 3. Build the isolation NSG once, by hand

The code never writes firewall rules. It only moves a VM's NIC onto this NSG, and refuses unless the
NSG is tagged `purpose=isolation`.

```bash
RG=rg-ctdip-demo; NSG=nsg-isolate-all; FORENSICS_IP=<your-public-ip>/32
az network nsg create -g $RG -n $NSG --tags purpose=isolation
az network nsg rule create -g $RG --nsg-name $NSG -n allow-forensics --priority 100 \
  --direction Inbound --access Allow --protocol Tcp --source-address-prefixes $FORENSICS_IP \
  --destination-port-ranges 22 3389
az network nsg rule create -g $RG --nsg-name $NSG -n deny-all-in --priority 4000 \
  --direction Inbound --access Deny --protocol '*' --source-address-prefixes '*' --destination-port-ranges '*'
az network nsg rule create -g $RG --nsg-name $NSG -n deny-all-out --priority 4000 \
  --direction Outbound --access Deny --protocol '*' --destination-address-prefixes '*' --destination-port-ranges '*'
az network nsg show -g $RG -n $NSG --query id -o tsv      # → ISOLATION_NSG_ID
```

Then `pip install azure-identity azure-mgmt-network azure-mgmt-compute` and add `ISOLATE_VM` to
`LIVE_ACTIONS`. NSGs are stateful: sessions already open may survive until idle. Prove isolation in the
demo with a new connection attempt, not an existing one. A subnet-level NSG still applies as well; the
NIC-level deny wins either way.

## 4. Allow the OAuth attack in the test tenant

Many tenants block user consent to unverified apps by default. In **Entra admin center → Enterprise
applications → Consent and permissions**, allow user consent for the test tenant only.

## 5. Stage the attacks

- **Scenario A:** register a multi-tenant "attacker" app in a second tenant (or the same one) requesting
  `Mail.Read Files.Read.All offline_access`. Sign in as the test user, consent, then use the token to
  read mail and download files (Graph Explorer or a short script).
- **Scenario B:** sign in as the test user through a VPN exit in a non-allowed country, register a new
  Authenticator method, create an inbox rule forwarding to an external address.
- **Scenario C:** as a Privileged Role Administrator test account, assign yourself Global Administrator,
  then add a client secret to an app registration.

Collect and save as soon as the records appear (Exchange/OneDrive can take hours):

```bash
python scripts/collect_live.py --hours 24 --save      # writes fixtures/z_capture_*.json (git-ignored)
```

## 6. Verify each live action once

| Action | Verified by | Caveat |
|---|---|---|
| Revoke OAuth grant | Follow-up GET on the grant returns 404 | Issued access tokens stay valid until expiry (about an hour) |
| Disable application | Service principal reads back `accountEnabled: false` | — |
| Revoke user sessions | Graph returns `value: true` | Cannot be read back; shown as "accepted, unverified" |
| Isolate VM | Every NIC reads back on the isolation NSG | Established sessions may persist |
