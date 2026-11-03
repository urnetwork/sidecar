# Sidecar product

The product is not released. This file follows the description given in the brief. It does not describe a shipped URnetwork app, API, or network feature.

## Your statement

URnetwork is launching a new agent sidecar that lets people get more out of their AI by making coordination, shared memory, direct-to-agent communication, and admin auditability easier and private.

The features are:

1. Real-time encrypted storage with a git front end, for context and project storage.
2. IP address and port forwarding for local services.
3. A public TLS edge.
4. An email inbox and group inbox / messaging.
5. Easy auth and team management.
6. An audit trail for an admin view.
7. It runs in userspace as a subprocess of any harness, with a text protocol interface to drive it.

## My understanding

The sidecar is a private process that sits beside the agent harness a team already runs. It is not itself the agent, and it does not replace Cursor, Claude Code, Copilot, Codex, or any other harness. Any of those can start it as a userspace subprocess and drive it through a text protocol.

The purpose in the statement is four jobs made easier, and kept private: coordination, shared memory, direct communication with agents, and an audit view for an admin. The seven features are how those jobs are delivered in one process.

**Shared memory and project context** are the encrypted store, reached through a git front end. Context and project files are what that store holds. “Real-time” means a change is available to the next reader without a separate publish step. Encryption is part of the store, not a later add-on.

**Direct communication** is the email inbox and the group inbox. People and agents use the same messaging surface. That is the coordination channel in the statement, alongside the shared store.

**Reaching local work** is port forwarding plus a public TLS edge. A service on the user’s machine can be called from outside that machine, on a TLS name. The statement includes both the forward and the public edge. It does not say the public name is the only way in, and it does not say the edge is private by default.

**Who may do this** is easy auth and team management. **What an admin can see** is the audit trail. Those two are the control and the record. The statement does not say the audit log includes prompts, tool arguments, or file diffs. It says there is an admin view.

**How a harness drives it** is the text protocol on the subprocess. The protocol is the interface to the sidecar. It is not described as a protocol the sidecar uses to talk to other agents, and it is not described as a replacement for MCP or for the harness’s own tools. “Any harness” means the sidecar is not locked to one vendor’s agent.

Privacy in the statement applies to the whole sidecar: coordination, memory, communication, and the admin record are easier and private. The statement does not say who holds the encryption keys, whether the model provider can see the working set the harness sends, or whether the public TLS edge is authenticated.

## What this understanding does not add

These are readings from later discussion, not features in the statement:

- A “run record” that commits the context diff, the route used, and the inbox message as one git commit.
- Write-back at the end of a run as a required step of the text protocol.
- Reach as a team grant recorded in that commit, with the public TLS name as an explicit publish.
- The group inbox as the way a human correction becomes the next commit.
- A file in the store for a failed check, so an outside eval tool can grade the run.

The statement also does not include a coding agent, an eval or trace product, a Salesforce or other system-of-record connector, or a claim that this combination is the only one available.
