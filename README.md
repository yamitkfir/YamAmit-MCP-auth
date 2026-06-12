# YamAmit-MCP-auth

## Project outline: MCP server authentication gaps

### Mission
Map authentication/authorization gaps in MCP servers with **independent tasks**.  
Each task must end with a binary conclusion:

- `This server has this gap`
- `This server does not have this gap`

### Working principles

1. **Increase difficulty gradually** (start with static checks, then behavioral testing).
2. **Automation first** (scripts/checklists/evidence templates over manual approvals).
3. Keep each task independent so tasks can run in parallel later.
4. For every claim, collect reproducible evidence (request/response, logs, config proof).

### External baseline used for gap mapping

- Model Context Protocol (MCP) security and authorization guidance
- OAuth 2.1 (RFC 9728) token and client security baseline
- OWASP API Security Top 10 (2023), especially authn/authz risks (API1, API2, API5)

### Task ladder (easy → hard)

| Task | Difficulty | Gap being checked | How to run independently | Required conclusion format |
|---|---|---|---|---|
| T1 | Easy | Missing auth on exposed MCP endpoints | Enumerate endpoints/transports from docs/config and confirm whether authentication is required on each | `Has/Does not have: unauthenticated endpoint access gap` |
| T2 | Easy | Insecure transport for auth data | Verify TLS/HTTPS requirement for every endpoint carrying credentials/tokens | `Has/Does not have: insecure transport auth gap` |
| T3 | Easy-Medium | Weak identity mechanism (static/shared credentials only) | Inspect configured auth methods and confirm support for modern identity flows (OAuth/OIDC/API token hygiene) | `Has/Does not have: weak authentication mechanism gap` |
| T4 | Medium | Broken token validation | Test invalid/expired/wrong-audience tokens and verify rejection behavior | `Has/Does not have: token validation gap` |
| T5 | Medium | Broken object-level authorization (BOLA) | Run cross-tenant/object access attempts using valid but unauthorized identities | `Has/Does not have: object-level authorization gap` |
| T6 | Medium-Hard | Broken function-level authorization (BFLA) | Attempt privileged operations with non-privileged roles/scopes | `Has/Does not have: function-level authorization gap` |
| T7 | Hard | Secret/token leakage in logs or tool outputs | Trigger failures and inspect logs/output for leaked tokens, keys, session IDs | `Has/Does not have: credential exposure gap` |
| T8 | Hard | Prompt/tool boundary abuse leading to auth bypass | Simulate prompt-injection/tool-misuse flows and verify permission boundaries are enforced | `Has/Does not have: prompt/tool boundary auth gap` |

### Standard task output template (for every T1-T8)

1. **Scope**: exact server/endpoint/role under test  
2. **Method**: command(s) + input used  
3. **Evidence**: raw responses/log excerpts  
4. **Result**: pass/fail for the specific gap  
5. **Conclusion**: `This server has/does not have this gap`

### Reducing human approval dependency

- Use a fixed test harness per task (same inputs, same expected outcomes).
- Store all evidence artifacts automatically (request/response + timestamp).
- Auto-generate per-task verdict files with only one manual step: final review.
- Prefer role/token fixtures and repeatable scripts over ad-hoc manual checks.