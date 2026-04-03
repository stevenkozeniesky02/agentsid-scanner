# The A2A Security Gap: Six Structural Vulnerabilities in the Agent Communication Standard

**AgentsID Research · April 2026**

---

## Abstract

Google's Agent2Agent (A2A) protocol, released as v1.0 in 2025, is the most credible attempt yet to standardize communication between AI agents. It references RFC 2119 correctly, cites real cryptographic standards, and includes a dedicated security considerations section that is more thorough than anything comparable. It is well-designed. It is also structurally insecure in six specific ways that developers building production agent systems need to understand before they ship.

This paper analyzes A2A v1.0 against the actual protocol specification and proto schema (the normative source per Section 1.4). We identify six gaps grounded in exact spec language: (1) the signing mechanism is self-attestation by design; (2) the push notification MUST requirement is conditioned on an optional field, making it void by default; (3) credential chains are architecturally exposed across delegation paths; (4) the `Part.url` field creates an unaddressed SSRF surface; (5) `reference_task_ids` enables cross-session context injection; and (6) there is no standard authorization model — each agent is an authorization island.

None of these are bugs in any implementor's code. They are in the spec itself.

---

## 1. Background

### 1.1 The Research Arc

This is the third paper in AgentsID's security series:

- **Paper 1** (*The State of MCP Server Security — 2026*): 15,983 MCP servers scanned. 72.6% scored below 60. No per-tool authorization, no input schema validation.
- **Paper 2** (*Weaponized by Design*): Five toxic flow patterns in MCP tool descriptions. Injection, exfiltration, and behavioral mandates in production servers by design.
- **Paper 3** (*The Multi-Agent Auth Gap*): Four structural gaps across five frameworks — Claude Code Agent Teams, AutoGen, CrewAI, LangGraph, OpenAI Agents SDK. Agent identity is a string. No credential scoping. No inter-agent auth.

A2A is the protocol being positioned to address these problems at the standard level. This paper evaluates whether it does.

### 1.2 Methodology

All findings cite the A2A v1.0 specification at `a2a-protocol.org/latest/specification` and the authoritative `specification/a2a.proto` at `github.com/google/A2A`. Where the spec and proto conflict or interact in non-obvious ways, we cite both. Proto field annotations — specifically `[(google.api.field_behavior) = REQUIRED]` — are the authoritative indicator of what is required versus optional, per Section 1.4: *"the file `spec/a2a.proto` is the single authoritative normative definition of all protocol data objects."*

All MUST/SHOULD/MAY language follows RFC 2119 as declared in Section 2.1.

---

## 2. The Six Gaps

### 2.1 Gap 1: JWS Signing Is Self-Attestation

**The claim:** Agent Cards can be digitally signed to prove authenticity.

**The reality:** The signing mechanism, as specified, proves nothing about the agent's legitimacy. It proves only that the person who published the card also controls the key used to sign it.

Here is the exact mechanism from Section 8.4.2:

```
The protected header MAY include:
  - `jku`: URL to JSON Web Key Set (JWKS) containing the public key
```

And from Section 8.4.3 (Signature Verification), step 2:

```
Retrieve the public key using the `kid` and `jku` (or from a trusted key store)
```

The `jku` URL — the location of the verification key — is provided by the Agent Card itself. An attacker publishing a malicious agent card does the following:

1. Generates an EC keypair
2. Hosts the public key at `https://attacker.example.com/agent/jwks.json`
3. Publishes an Agent Card claiming to be "Stripe PaymentsProcessor" with `jku` pointing to their JWKS
4. Signs the card with the private key
5. Sets `signatures[0].protected` = base64url of `{"alg":"ES256","typ":"JOSE","kid":"key-1","jku":"https://attacker.example.com/agent/jwks.json"}`

A client that follows the spec's signature verification procedure (`SHOULD verify at least one signature`) fetches `attacker.example.com/agent/jwks.json`, gets the attacker's public key, and the verification **succeeds**. The signature is valid. The agent is indistinguishable from a real Stripe agent to any client following the spec.

The spec does offer an alternative:

```
Clients MAY maintain a trusted key store for known agent providers
```

`MAY`. Not `MUST`. Not `SHOULD`. The out is optional, and the trusted key store isn't defined — there's no standard format, no standard registry, and no guidance on how to populate one.

The only protection against this attack is TLS certificate validation for the Agent Card endpoint (Section 7.2). But Section 7.2 says:

```
A2A Clients SHOULD verify the A2A Server's identity by validating its TLS certificate against trusted certificate authorities (CAs) during the TLS handshake.
```

`SHOULD`, not `MUST`. And TLS validates the domain, not the agent's claimed identity. `attacker.example.com` can have a valid TLS cert while claiming to be Stripe.

**The combined failure:** Signing is optional (`MAY`). Verification is optional (`SHOULD`). The key source is controlled by the agent being verified. There is no trusted key registry. Every protection in the chain is optional, and the cryptographic mechanism itself is self-referential.

**Spec citations:**
- Section 8.4: `"Agent Cards MAY be digitally signed"`
- Section 8.4.2: `jku` field is `MAY`
- Section 8.4.3: `"Clients SHOULD verify at least one signature before trusting an Agent Card"`
- Section 8.4.3: `"Clients MAY maintain a trusted key store for known agent providers"`
- Section 7.2: `"A2A Clients SHOULD verify the A2A Server's identity"` (SHOULD)

---

### 2.2 Gap 2: The Conditional MUST That Voids Itself

**The claim:** Push notification authentication is required.

**The reality:** The MUST requirement is conditioned on an optional proto field. When that field is absent — which is the default — the MUST has no referent and cannot be enforced.

From Section 13.2 (Push Notification Security):

```
Clients MUST validate webhook authenticity using the provided authentication credentials
```

This is unambiguous. MUST. Required by RFC 2119.

Now look at the `TaskPushNotificationConfig` proto message (authoritative per Section 1.4):

```protobuf
message TaskPushNotificationConfig {
  string tenant = 1;
  string id = 2;
  string task_id = 3;
  string url = 4 [(google.api.field_behavior) = REQUIRED];
  string token = 5;                  // no REQUIRED annotation — optional
  AuthenticationInfo authentication = 6;  // no REQUIRED annotation — optional
}
```

Only `url` carries `[(google.api.field_behavior) = REQUIRED]`. The `authentication` field is optional by the authoritative normative definition.

This creates the following interaction: a client registers a webhook without specifying `authentication`. The `authentication` field is absent. Section 13.2 says "MUST validate webhook authenticity using the provided authentication credentials" — but there are no provided authentication credentials. The MUST refers to a void set. There is nothing to validate.

There is a further contradiction within the spec itself. Section 4.3.3 (Push Notification Payload) states:

```
Clients SHOULD implement appropriate security measures to verify the notification source
```

`SHOULD` in Section 4.3.3. `MUST` in Section 13.2. These describe the same security control with inconsistent requirement levels. A developer reading Section 4.3.3 — where the push notification behavior is defined — sees `SHOULD`. Only a developer who reads both the behavior section AND the security considerations section sees `MUST`, and then discovers the MUST is conditioned on an optional field.

**The attack:** Any server that knows a target's webhook URL and a valid task ID can POST a `task.completed` or `task.failed` notification. If no authentication was configured, the receiving client has no basis to reject it. The client MUST respond with HTTP 2xx (Section 4.3.3), effectively acknowledging a forged event.

**Spec citations:**
- Section 13.2: `"Clients MUST validate webhook authenticity using the provided authentication credentials"`
- Section 4.3.3: `"Clients SHOULD implement appropriate security measures to verify the notification source"`
- `a2a.proto`: `TaskPushNotificationConfig.authentication` — no `REQUIRED` annotation

---

### 2.3 Gap 3: Credential Chains Are Acknowledged and Optional to Fix

**The claim:** A2A supports multi-agent pipelines with in-task authorization delegation.

**The reality:** The spec explicitly documents that credential forwarding exposes credentials to every agent in the chain, and all mitigations are `SHOULD`.

Section 7.6.3 (In-Task Authorization Security Considerations), verbatim:

```
In-band credential exchange can allow credentials to be passed across chains of multiple A2A agents,
exposing those credentials to each agent participating in the chain.

If using in-band credential exchange, we recommend adhering to the following security practices:

- Credentials SHOULD be bound to the agent which originated the request, such that only this agent
  is able to use the credentials.
- Credentials containing sensitive information SHOULD be only readable by the agent which
  originated the request, such as by encrypting the credential.
```

Three observations:

**First**, "we recommend" is not RFC 2119 language. The spec authors are stepping outside the normative language here deliberately, signaling this is guidance rather than requirement.

**Second**, both mitigations are `SHOULD`, not `MUST`. An implementation that passes credentials in-band without binding or encryption is fully spec-compliant.

**Third**, "encrypting the credential" so only the originating agent can read it requires the originating agent to have a published encryption key, every intermediate agent to honor it, and a standardized credential envelope format. None of these are defined by the spec. The mitigation is described in one sentence without any mechanism.

**The chain model in practice:**

```
User → Orchestrator (receives API key K)
Orchestrator → DataAgent (K forwarded as in-band credential)
DataAgent → StorageAgent (K forwarded again)
```

`StorageAgent` now has credential `K`. Nothing in the protocol prevents this. The user granted `K` to the Orchestrator. They did not grant it to DataAgent or StorageAgent. There is no way for the user to know it was forwarded. There is no way for the Orchestrator to prevent it being forwarded further.

Combined with the opacity design principle ("agents collaborate without needing to share their internal thoughts, plans, or tool implementations"), an orchestrator has zero visibility into what a sub-agent does with the credentials it receives.

**Spec citations:**
- Section 7.6.3: in-band credential exposure acknowledged, SHOULD mitigations
- Section 1.2: "Opaque Execution: Agents collaborate based on declared capabilities and exchanged information, without needing to share their internal state, memory, or tools."

---

### 2.4 Gap 4: `Part.url` Is an Unaddressed SSRF Surface

**The claim:** A2A supports rich content exchange via the `Part` type, which can contain URLs pointing to file content.

**The reality:** The `Part` proto has a `url` field for pointing to file content. The spec's SSRF guidance applies only to webhook URLs. Any A2A server that fetches content from Part URLs — which is the purpose of the field — operates outside the spec's SSRF protection guidance.

The `Part` proto:

```protobuf
message Part {
  oneof content {
    string text = 1;
    bytes raw = 2;
    string url = 3;      // "A URL pointing to the file's content"
    google.protobuf.Value data = 4;
  }
  google.protobuf.Struct metadata = 5;
  string filename = 6;
  string media_type = 7;
}
```

The spec's SSRF guidance lives in Section 13.2 (Push Notification Security):

```
Agents SHOULD validate webhook URLs to prevent SSRF (Server-Side Request Forgery) attacks:
  - Reject private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
  - Reject localhost and link-local addresses
  - Implement URL allowlists where appropriate
```

This guidance explicitly applies to webhook URLs — `PushNotificationConfig.url`. There is no corresponding guidance for `Part.url`.

An agent that processes messages and fetches the content at `Part.url` can be directed to:
- `http://169.254.169.254/latest/meta-data/` — AWS instance metadata
- `http://metadata.google.internal/computeMetadata/v1/` — GCP metadata endpoint
- `http://10.0.0.1/admin` — internal network resources
- `file:///etc/passwd` — local file access (if the agent resolves file URIs)

The attack is simple: send a message with a Part whose `url` field points to an internal resource. If the agent fetches it — which it will, since that is the field's purpose — it performs an SSRF on the attacker's behalf.

The spec does say in Section 13.4:

```
Agents SHOULD implement appropriate limits on message sizes, file sizes, and request complexity
Agents SHOULD sanitize or validate file content types and reject unexpected media types
```

Neither of these addresses URL validation for `Part.url`. The gap is specific and unaddressed.

**Spec citations:**
- Section 13.2: SSRF guidance scoped to webhook URLs only
- Section 13.4: Input validation guidance — no mention of Part URL validation
- `a2a.proto`: `Part.url` — no REQUIRED annotation, no validation annotation

---

### 2.5 Gap 5: `reference_task_ids` Enables Cross-Session Context Injection

**The claim:** A2A's `Message` type supports `reference_task_ids` for providing additional context from related tasks.

**The reality:** If an A2A server agent fetches and incorporates the content of referenced tasks when building its context, an attacker who can create tasks can inject content into another agent's operational context.

The `Message` proto:

```protobuf
message Message {
  string message_id = 1 [(google.api.field_behavior) = REQUIRED];
  string context_id = 2;
  string task_id = 3;
  Role role = 4 [(google.api.field_behavior) = REQUIRED];
  repeated Part parts = 5 [(google.api.field_behavior) = REQUIRED];
  google.protobuf.Struct metadata = 6;
  repeated string extensions = 7;
  repeated string reference_task_ids = 8;   // "A list of task IDs that this message references for additional context"
}
```

And from Section 3.2.5 (Metadata):

```
A flexible key-value map for passing additional context or parameters with operations.
Metadata keys and are strings and values can be any valid value that can be represented in JSON.
```

The `metadata` field on `Task`, `Message`, `Artifact`, `Part`, and `SendMessageRequest` is `google.protobuf.Struct` — arbitrary JSON with no defined schema, no size constraint in the proto, and no validation guidance beyond the general `SHOULD implement appropriate limits` in Section 13.4.

**The attack scenario:** An attacker creates a task with carefully crafted content — a prompt injection payload embedded in an artifact or message history. They note the task ID. They then send a legitimate-looking message to a target agent with `reference_task_ids = ["attacker-task-id"]`. If the target agent's implementation fetches referenced tasks to provide context to the model, it incorporates the attacker's payload.

This is architecturally distinct from direct injection (sending malicious content in the current message) because:
1. The malicious content is in a separate, pre-existing task that may have passed any per-message filtering
2. The reference appears as legitimate context enrichment
3. The spec provides no guidance on scope-limiting what referenced tasks can contain

The spec does not say agents MUST fetch referenced tasks — it says `reference_task_ids` is for "additional context." But agents that do fetch them to provide richer context have no spec guidance on validation.

**Spec citations:**
- `a2a.proto`: `Message.reference_task_ids` field 8 — no validation constraint
- `a2a.proto`: `google.protobuf.Struct metadata` on all major objects — arbitrary JSON
- Section 13.4: No guidance on `reference_task_ids` validation

---

### 2.6 Gap 6: Every Agent Is an Authorization Island

**The claim:** A2A provides enterprise-ready authorization.

**The reality:** A2A provides enterprise-ready *authentication*. Authorization is entirely undefined at the protocol level.

Section 13.1 (Data Access and Authorization Scoping) explicitly specifies the scope of authorization requirements:

```
Authorization models are agent-defined and MAY be based on:
  - User identity (user-based authorization)
  - Organizational roles or groups (role-based authorization)
  - Project or workspace membership (project-based authorization)
  - Organizational or tenant boundaries (multi-tenant authorization)
  - Custom authorization logic specific to the agent's domain
```

The `MAY be based on` language means there is no required authorization model. An agent can implement any authorization scheme (or none) and be spec-compliant. The protocol enforces nothing about what authenticated clients are allowed to do.

The spec does require:

```
Servers MUST implement authorization checks on every A2A Protocol Operations request
Implementations MUST scope results to the caller's authorized access boundaries as defined by
the agent's authorization model
```

But what "the agent's authorization model" means is entirely up to the implementor. An agent that grants all authenticated clients access to all tasks has an authorization model. It's a bad one, but it satisfies the spec.

**Why this is structural, not implementation:** In a multi-agent system, agents from different organizations connect to each other. Org A's orchestrator connects to Org B's specialist agent. Org B's agent has an authorization model. Org A's orchestrator has an authorization model. These models are independent and may be incompatible. There is no standard for:

- How Org A's orchestrator declares what its agent is authorized to request
- How Org B's agent validates that an incoming request is in scope
- How either party verifies the authorization claims of the other
- What format authorization context takes when propagated across agent boundaries

Compare to OAuth2, which solves this for web applications: a standard token format (JWT), a standard scope format, a standard introspection endpoint, a standard token exchange mechanism. A2A has none of these for agent authorization. Every cross-org agent connection is an authorization negotiation that has to be designed from scratch outside the protocol.

**The enterprise readiness gap:** The `enterprise-ready.md` doc says:

```
Skill-Based Authorization: Access can be controlled on a per-skill basis, as advertised in the
Agent Card. For example, specific OAuth scopes SHOULD grant an authenticated client access to
invoke certain skills but not others.
```

`AgentSkill` in the proto does have a `security_requirements` field:

```protobuf
message AgentSkill {
  string id = 1 [(google.api.field_behavior) = REQUIRED];
  string name = 2 [(google.api.field_behavior) = REQUIRED];
  string description = 3 [(google.api.field_behavior) = REQUIRED];
  repeated string tags = 4 [(google.api.field_behavior) = REQUIRED];
  repeated string examples = 5;
  repeated string input_modes = 6;
  repeated string output_modes = 7;
  repeated SecurityRequirement security_requirements = 8;
}
```

Per-skill security requirements exist in the schema. But their enforcement is not required. There is no MUST that says servers must reject invocations that don't satisfy declared skill security requirements. An agent can declare `security_requirements` for a skill and still honor invocations that don't satisfy them — and be spec-compliant.

**Spec citations:**
- Section 13.1: "Authorization models are agent-defined and MAY be based on..."
- `enterprise-ready.md`: skill-based authorization uses `SHOULD`
- `a2a.proto`: `AgentSkill.security_requirements` field 8 — no enforcement language

---

## 3. Pattern Analysis

### 3.1 The Consistent Structure of These Gaps

All six gaps share a common pattern:

| Gap | Mechanism Defined | Mechanism Required |
|-----|-------------------|--------------------|
| JWS signing | Yes — complete JWS format | No — `MAY` |
| JWS verification | Yes — complete verification steps | No — `SHOULD` |
| Push notification auth | Yes — `AuthenticationInfo` object | No — field is optional proto |
| Credential binding | Yes — described in prose | No — `SHOULD` |
| Part URL validation | No | — |
| Reference task scoping | No | — |
| Authorization standard | No | — |

The first four gaps are partially designed: the mechanism exists and is correct, but its use is not required. The last three gaps are entirely absent: the mechanism isn't specified at all, and there's no SHOULD or MAY pointing developers toward a solution.

This is not negligence. The A2A specification is detailed, thoughtful, and cites real standards. These are deliberate tradeoffs to maximize adoption by keeping the compliance bar low.

### 3.2 Comparing the Spec's Own Confidence Levels

The spec applies `MUST` confidently in areas the authors consider core to protocol function:

- `Servers MUST authenticate every incoming request` (Section 7.4)
- `Production deployments MUST use encrypted communication` (Section 7.1)
- `Implementations MUST implement appropriate authorization scoping` (Section 3.1.4)
- `The operation MUST establish a webhook endpoint` (Section 3.1.7)
- `Clients MUST respond with HTTP 2xx status codes` (Section 4.3.3)

Where the authors are less confident — or where enforcement would create adoption barriers — they use `SHOULD`:

- `SHOULD verify the A2A Server's identity` (Section 7.2) — not MUST
- `SHOULD verify at least one signature` (Section 8.4.3) — not MUST
- `SHOULD implement appropriate security measures to verify the notification source` (Section 4.3.3) — not MUST

The pattern is: operational correctness is `MUST`. Security is `SHOULD`.

### 3.3 The Series Pattern

This is the fourth paper documenting the same structural dynamic across the agent stack:

| Layer | What's Optional | Paper |
|-------|-----------------|-------|
| MCP tools | All authorization | Paper 1 |
| MCP tool descriptions | Injection/exfil prevention | Paper 2 |
| Orchestration frameworks | Agent identity, credential scoping | Paper 3 |
| A2A protocol standard | Signing, verification, authorization model | Paper 4 |

The pattern is consistent across MCP (a tool protocol), five production frameworks, and A2A (an agent communication protocol). Security is treated as the developer's responsibility at every layer, with no enforcement primitives in the spec. The practical result is systematic insecurity across the industry.

---

## 4. What Changes Would Fix This

The fixes are not architectural rewrites. Most require changing requirement levels or adding short normative sections.

**Gap 1 — JWS self-attestation:**
Two changes: (1) Change `MAY be digitally signed` to `SHOULD be digitally signed` for agents operating in non-private environments. (2) Add a `SHOULD` requirement for a trusted key store: *"Clients SHOULD maintain a trusted set of agent provider JWKS URLs and MUST NOT treat signatures as valid when `jku` points to an untrusted domain."*

**Gap 2 — Conditional MUST:**
Remove the contradiction between Section 4.3.3 (SHOULD) and Section 13.2 (MUST). Pick one. Then: if `authentication` is not configured in `TaskPushNotificationConfig`, the spec SHOULD require clients to generate a random token and validate it as an `X-Webhook-Secret` header. This is standard practice in every major webhook API.

**Gap 3 — Credential chains:**
Change both `SHOULD` mitigations in Section 7.6.3 to `MUST`. Add a standardized credential envelope format: a JSON object with `encrypted_for` (the originating agent's public key ID) and `ciphertext` fields. Without a standardized format, the mitigation cannot be implemented interoperably.

**Gap 4 — Part URL SSRF:**
Add to Section 13.4 (or create Section 13.5): *"Agents MUST validate `Part.url` values before fetching content. Agents MUST NOT fetch URLs pointing to private IP ranges, localhost, or link-local addresses. Agents SHOULD implement URL allowlists for Part content fetching."*

**Gap 5 — `reference_task_ids` injection:**
Add a `SHOULD` to Section 3.2 or Section 13: *"Agents SHOULD validate that referenced task IDs belong to the same context as the current task, or are explicitly authorized for cross-context reference, before incorporating referenced content into agent context."*

**Gap 6 — Authorization vacuum:**
This is the hardest fix because it requires a new specification component. The minimum viable change: define a standard `DelegationClaims` extension object that orchestrators can include with task creation to declare the authorization scope of the delegation. Sub-agents that support the extension MUST honor it. Sub-agents that don't support it MAY ignore it. Adoption can be gradual.

---

## 5. Conclusion

A2A v1.0 is more security-conscious than any agent communication protocol that preceded it. The security considerations section is real, the cryptographic mechanisms are correct, and the spec authors clearly understand the threat model. These are not the findings of a negligently designed protocol.

They are the findings of a protocol designed to achieve broad adoption, where security is SHOULD and interoperability is MUST. That is a rational engineering tradeoff. It is not a safe one.

Developers building production multi-agent systems on A2A today should audit their implementations against these six gaps specifically:

1. Do you verify Agent Card signatures? If so, do you maintain a trusted key store, or do you blindly trust `jku`?
2. Do your push notification webhook endpoints require authentication? Is that authentication configured in `TaskPushNotificationConfig.authentication`, or did you register the webhook without it?
3. Can credentials provided to your orchestrator reach sub-agents you didn't intend to share them with?
4. Do you fetch content from `Part.url` fields? Do you validate those URLs before fetching?
5. Do you incorporate `reference_task_ids` content into agent context? From which sources?
6. What is your authorization model for incoming A2A requests? Does it match the authorization expectations of the clients connecting to you?

Each of these is a question the spec leaves entirely to the implementor. Most production implementations won't answer them. Our prior research — 72.6% of MCP servers below 60, four auth gaps across five frameworks — suggests what happens when security is SHOULD at every layer of the stack.

---

## Appendix: Spec Language Reference

All citations are from A2A Protocol Specification v1.0 (`a2a-protocol.org/latest/specification`) and `specification/a2a.proto` in the `google/A2A` repository. MUST/SHOULD/MAY follow RFC 2119 as declared in Section 2.1.

| Finding | Spec Location | Exact Language |
|---------|--------------|----------------|
| Signing is optional | Section 8.4 | `"Agent Cards MAY be digitally signed"` |
| Verification is optional | Section 8.4.3 | `"Clients SHOULD verify at least one signature"` |
| Key trust is optional | Section 8.4.3 | `"Clients MAY maintain a trusted key store"` |
| `jku` is attacker-controlled | Section 8.4.2 | `jku` described as MAY include; no trust constraint |
| Server identity verification | Section 7.2 | `"A2A Clients SHOULD verify the A2A Server's identity"` |
| Push auth MUST | Section 13.2 | `"Clients MUST validate webhook authenticity using the provided authentication credentials"` |
| Push auth SHOULD | Section 4.3.3 | `"Clients SHOULD implement appropriate security measures to verify the notification source"` |
| `authentication` is optional | `a2a.proto` | `TaskPushNotificationConfig.authentication` — no `[(google.api.field_behavior) = REQUIRED]` |
| Credential chain acknowledgment | Section 7.6.3 | `"In-band credential exchange can allow credentials to be passed across chains of multiple A2A agents"` |
| Credential binding | Section 7.6.3 | `"Credentials SHOULD be bound to the agent which originated the request"` |
| SSRF guidance scope | Section 13.2 | Webhook URLs only — no mention of `Part.url` |
| `reference_task_ids` | `a2a.proto` | `Message.reference_task_ids` — no validation constraint |
| Authorization freedom | Section 13.1 | `"Authorization models are agent-defined and MAY be based on..."` |
| Skill auth enforcement | `a2a.proto` | `AgentSkill.security_requirements` — no enforcement annotation |

---

*AgentsID is building the permission and identity layer for AI agents. Scan any MCP server at agentsid.dev/registry. Security research: agentsid.dev/blog.*
