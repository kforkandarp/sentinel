# Engineering Decisions

This document records the significant engineering decisions made while building Sentinel. It explains the reasoning behind the architecture, the alternatives that were not chosen, and the trade-offs that remain.

It intends to provide context beyond the source code and explain the engineering thought process.

---

## Why this project?

AI agents are increasingly moving beyond generating text and into workflows where they can browse external content, make decisions, and take consequential actions. That creates a different security problem from traditional prompt injection: what happens when the information influencing an agent's reasoning is not trustworthy?

Recent incidents and security research have shown that agents with access to payments, purchases, or other actions can be influenced by unexpected instructions embedded in external content. The important question is not whether every malicious instruction can be detected perfectly — it is what happens when detection fails.

I built **Sentinel** to explore that boundary.

The goal is to ensure that untrusted content can influence what an agent *thinks*, without independently giving it permission to *act*. Sentinel therefore separates probabilistic prompt-injection detection from deterministic authorization, using explicit task scope, spending limits, category restrictions, action fingerprints, and execution-time authorization checks.

Throughout the project, I deliberately prioritized:

- **authorization boundaries over detector confidence**
- **deterministic security rules over probabilistic decisions**
- **explicit action validation over direct agent execution**
- **failure visibility over hiding model limitations**

The result is a security gateway designed around a simple principle:

> **Untrusted content may influence agent reasoning, but it cannot independently grant execution authority.**

The engineering decisions that follow explain how that boundary is implemented and the trade-offs behind it.

---

## 1. Separate Detection from Authorization

### Context

Prompt-injection detection is inherently probabilistic. A classifier produces a prediction and confidence score; it cannot provide an absolute security guarantee.

Authorization, however, is a security-sensitive control with explicit constraints such as spending limits, allowed categories, and delegated task scope.

Treating these as the same decision would make the authorization boundary dependent on the correctness of a probabilistic model.

### Decision

Sentinel separates:

- **probabilistic threat detection**
- **deterministic authorization**

The detector determines whether content exhibits characteristics associated with prompt injection.

The PolicyGate independently determines whether a proposed action is authorized.

```text
Untrusted Content
       |
       v
Inspection / Detection
       |
       v
Action Proposal
       |
       v
Deterministic PolicyGate
       |
       v
   Executor
```

### Why

The detector answers:

> "Does this content look malicious?"

The PolicyGate answers:

> "Is this action authorized under the current security policy?"

These are different questions and therefore should not share the same authority.

### Consequence

A detector false negative does not automatically grant unrestricted execution authority.

However, policy enforcement cannot eliminate every possible prompt-injection consequence. If an injection is missed and the resulting action remains within the authorized category and spending constraints, the action may still be allowed.

This limitation is explicitly documented rather than hidden behind the detector's confidence score.

## 2. Use Deterministic Policy Enforcement for Financial Authorization

### Context

Financial authorization has a bounded and explicitly defined decision space.

Sentinel needs to enforce spending limits, category restrictions, task scope, and escalation rules consistently.

### Decision

The PolicyGate uses deterministic rules rather than asking an LLM to decide whether an action should be authorized.

The current spending policy is:

| Condition | Decision |
|---|---|
| Amount <= ₹5,000 | ALLOW, subject to authorization checks |
| ₹5,000 < Amount <= ₹50,000 | REVIEW |
| Amount > ₹50,000 | DENY |

Additional deterministic checks include:

- requested category must match the authorized category
- optional maximum budget must not be exceeded
- a detector injection flag prevents automatic ALLOW and routes the action to REVIEW
- an ALLOW decision must contain a valid gate-issued authorization token

### Why

Deterministic rules provide:

- predictable behavior
- explicit security boundaries
- reproducible decisions
- straightforward testing
- auditable authorization logic

An LLM may be useful for interpreting ambiguous natural-language intent, but the final spending authorization should not depend on probabilistic model behavior.

### Alternative Not Chosen

Using an LLM as the final authorization authority was not chosen because the current authorization conditions are already expressible as explicit security rules.

### Consequence

The policy layer cannot independently understand arbitrary natural-language intent. Its strength is that once an action has been represented structurally, its authorization decision is deterministic and reproducible.

## 3. Treat Probabilistic Detection as Security Evidence

### Context

Sentinel uses a pretrained prompt-injection classifier to identify potentially malicious content.

The classifier produces a label and score rather than a proof of maliciousness or safety.

### Decision

Detector output is treated as security evidence, not as an authorization credential.

Conceptually:

```text
Detector
   |
   +-- label
   +-- confidence score
   +-- threshold
   |
   v
PolicyGate
```

rather than:

```text
Detector == SAFE
       |
       v
    Execute
```

### Why

The system explicitly distinguishes:

> "The model estimates that this content is likely safe."

from:

> "This action satisfies the configured authorization policy."

The second statement controls execution.

### Consequence

Improving detector accuracy improves the inspection layer, but does not remove the need for deterministic authorization.

## 4. Introduce an Inspection Router Before Model Inference

### Context

Not every request requires full ML-based inspection.

Some requests can be rejected through deterministic checks, while previously inspected content may be eligible for cache reuse.

Running the detector for every request would also make the model an unnecessary mandatory dependency.

### Decision

All `/scan` requests pass through the InspectionRouter.

The router can produce:

- `BLOCK`
- `CACHE_REUSE`
- `DEEP_INSPECT`

The decision is based on:

- deterministic blocking conditions
- content integrity
- provenance
- cache state

```text
Request
   |
   v
InspectionRouter
   |
   +----> BLOCK
   |
   +----> CACHE_REUSE
   |
   +----> DEEP_INSPECT
                |
                v
             Detector
```

### Why

The router establishes a deterministic control point before probabilistic inference.

It allows Sentinel to reject invalid inputs early, reuse trusted inspection observations where appropriate, and invoke the detector only when deeper inspection is required.

### Consequence

The detector is no longer responsible for every request path.

The router itself becomes part of the security boundary and must therefore remain deterministic and auditable.

## 5. Establish Content Identity and Provenance Before Reuse

### Context

Inspection results are only meaningful if the system knows which content was inspected.

A cached detector result cannot safely be treated as globally reusable for arbitrary content.

### Decision

Ingestion establishes canonical content, computes a SHA-256 content hash, and associates the content with provenance information.

The resulting identity is used when reasoning about inspection reuse.

```text
Source
   |
   v
Canonical Content
   |
   +----> SHA-256 Content Hash
   |
   +----> Provenance
   |
   v
Inspection
```

### Why

The content hash provides a deterministic identity for the content being inspected.

Provenance provides the context in which that content was obtained.

Together they allow Sentinel to distinguish previously inspected content from different content that merely looks similar.

### Consequence

Inspection reuse is scoped to content/provenance identity rather than treated as a global "this detector result is safe" cache.

## 6. Bind Authorization to the Exact Action Being Executed

### Context

Authorization must apply to the exact action that reaches the Executor.

Checking the action only at the PolicyGate is insufficient if the action representation can subsequently be modified before execution.

### Decision

ActionProposal generates a SHA-256 fingerprint over its security-relevant action fields.

The authorization decision is associated with that fingerprint.

The Executor verifies that the proposal presented for execution still corresponds to the proposal that was authorized.

### Example

Suppose the configured authorization limit were higher than the current example.

An action is initially authorized as:

```text
Amount: ₹4,000
```

The PolicyGate evaluates that proposal and produces:

```text
H1 = SHA256(authorized_action)
```

If the proposal is subsequently modified:

```text
Amount: ₹40,000
```

the resulting fingerprint becomes:

```text
H2 = SHA256(modified_action)
```

Since:

```text
H1 != H2
```

the Executor rejects the modified proposal.

In this case, the fingerprint protects the integrity of the authorization-to-execution boundary.

### Why

The PolicyGate answers:

> "Was this exact action authorized?"

The fingerprint allows the Executor to verify:

> "Is this still the exact action that was authorized?"

### Important Distinction

The fingerprint is not a replacement for spending-policy enforcement.

If an action is already ₹40,000 and the configured policy does not permit it, the PolicyGate should reject or escalate it based on the policy.

The fingerprint protects against a different failure mode:

an authorized action being changed after authorization.

### Consequence

Authorization is bound to the exact action representation through its SHA-256 fingerprint rather than merely to a mutable set of action fields.

## 7. Keep Inspection State Separate from Authorization State

### Context

Repeatedly running the same detector over identical trusted content is unnecessary.

However, caching an authorization decision would be dangerous because authorization depends on the current action and authorization context.

Detection state and authorization state therefore have different security semantics.

### Decision

Sentinel caches detector observations, not PolicyGate decisions.

On a cache miss:

```text
DEEP_INSPECT
     |
     v
Detector
     |
     v
Cache detector observation
```

On a cache hit:

```text
CACHE_REUSE
     |
     v
Reuse detector observation
     |
     v
Skip detector inference
```

The PolicyGate still evaluates the action for every request.

### Why

A detector observation is associated with inspected content.

An authorization decision is associated with a specific action and current authorization context.

Those lifecycles are different and should not share the same cache.

### Consequence

Cache reuse can avoid repeated model inference without allowing an old authorization decision to bypass current policy evaluation.

Policy evaluation remains request-specific even when inspection inference is reused.

## 8. Use ActionProposal as the Boundary Before Execution

### Context

The agent's desired action should not directly become an executable operation.

The system needs an intermediate representation that can be validated, fingerprinted, and authorized before execution.

### Decision

Sentinel represents intended actions through ActionProposal.

The proposal validates action-level properties including:

- currency
- quantity
- total amount
- required action fields

It also provides the action fingerprint used by the authorization/execution boundary.

```text
Agent Intent
    |
    v
ActionProposal
    |
    +----> Validation
    |
    +----> Fingerprint
    |
    v
PolicyGate
    |
    v
Executor
```

### Why

This creates an explicit boundary between:

what the agent proposes

and:

what the system permits to execute.

It also gives the PolicyGate and Executor a structured representation rather than requiring them to interpret free-form model output.

### Consequence

The agent does not receive direct execution authority merely because it generated a valid-looking action.

## 9. Keep the Executor Non-Authoritative

### Context

Multiple components making independent authorization decisions can create inconsistent security paths.

### Decision

The Executor does not independently decide whether an action is allowed.

It verifies that the execution request corresponds to a valid ALLOW decision and validates:

- correlation identity
- decision state
- proposal fingerprint
- gate-issued authorization token

Only then can execution proceed.

```text
ActionProposal
      |
      v
PolicyGate
      |
      +---- REVIEW / DENY ----> No execution
      |
      +---- ALLOW
             |
             v
          Executor
```

### Why

The PolicyGate is the authorization authority.

The Executor is responsible for enforcing the output of that authority.

This produces a single explicit authorization path.

### Consequence

A caller cannot legitimately bypass the PolicyGate simply by invoking the execution layer with an otherwise valid-looking action.

## 10. Treat TaskScope as Explicit Delegated Authorization Context

### Context

An action must be evaluated against what the user has actually authorized the agent to do.

Sentinel models this authorization scope explicitly through TaskScope.

### Decision

TaskScope represents the user-delegated authorization context used by the PolicyGate.

The current implementation supplies this context through the prototype request boundary.

The PolicyGate uses it to evaluate:

- allowed category
- maximum authorized budget
- task scope requirements

### Why

Authorization should be represented explicitly rather than inferred solely from the agent's natural-language reasoning.

This also makes the policy decision inspectable and testable.

### Current Boundary

The current TaskScope is not independently authenticated.

It is an explicit authorization context consumed by the policy layer, but the surrounding identity and integrity mechanism required to establish that context securely is outside the current implementation.

### Production Evolution

A production deployment would derive this authorization context from an authenticated and integrity-protected identity/capability layer rather than trusting a request-supplied authorization object.

## 11. Fail Closed on Security-Critical Inspection Errors

### Context

A detector failure must not silently become equivalent to a SAFE classification.

### Decision

Prompt-injection detection fails closed when model inference encounters an error.

The system does not convert an inspection failure into a successful safety result.

### Why

There is an important distinction between:

Model result:

```text
SAFE
```

and:

Model result:

```text
UNAVAILABLE
```

Treating both as SAFE would convert an availability failure into a security failure.

### Consequence

Inspection failures can reduce availability, but they do not silently weaken the security boundary.

## 12. Use a Pretrained Detector Today, Preserve a Path to Domain Adaptation

### Context

Sentinel currently uses the locked:

```text
protectai/deberta-v3-base-prompt-injection-v2
```

with a fixed threshold of 0.5.

The detector is evaluated independently from the authorization policy.

### Decision

The current detector remains a fixed external pretrained model rather than being fine-tuned as part of the current implementation.

The model's output is treated as probabilistic evidence and evaluated using a frozen benchmark.

### Why

Keeping the detector fixed makes the evaluation reproducible and makes it possible to distinguish:

- changes to the detection model
- changes to the surrounding security architecture

### Observed Limitation

The evaluation shows that the detector is not perfect, particularly for indirect and document-oriented injection patterns.

Therefore, the architecture does not assume that detector accuracy is sufficient to establish authorization.

### Future Model Improvement

A Sentinel-specific detector could be fine-tuned on a domain-specific dataset containing:

- direct prompt injections
- indirect prompt injections
- document-borne injections
- web-content injections
- commerce-specific manipulation attempts
- benign financial instructions
- hard negatives
- adversarially constructed examples

A potential training/evaluation pipeline would be:

```text
Domain Corpus
      |
      v
Security Label Taxonomy
      |
      v
Hard-Negative Mining
      |
      v
Supervised Fine-Tuning
      |
      v
Validation
      |
      v
Probability Calibration
      |
      v
Adversarial Evaluation
      |
      v
Threshold Selection
      |
      v
Frozen Test Set
```

Fine-tuning could improve domain-specific recall and reduce false negatives, but it would introduce additional concerns including:

- dataset bias
- overfitting
- distribution shift
- calibration drift
- adversarial generalization
- maintenance of the training corpus

Most importantly, a stronger detector would still remain a probabilistic inspection layer, not the authorization authority.

## 13. Current Capability Mechanism and Production Evolution

### Current Implementation

The current authorization capability is represented through an in-process gate-issued token and validation path.

The Executor verifies that the authorization information corresponds to the expected request and action fingerprint.

This provides an explicit authorization handoff between the PolicyGate and Executor.

### Production Evolution

A production deployment would require stronger capability semantics, including mechanisms such as:

- cryptographically signed capabilities
- explicit capability scope
- expiration
- nonce or replay protection
- distributed verification
- durable audit storage
- authenticated principal identity

These are production evolution paths rather than capabilities claimed by the current implementation.

## 14. Evaluate the Detector to Expose Architectural Weaknesses

### Context

Sentinel's detector evaluation uses a frozen benchmark containing both SAFE and INJECTION examples.

The current benchmark contains:

- 240 examples
- 120 SAFE
- 120 INJECTION
- fixed detector configuration
- fixed threshold

### Decision

The detector is evaluated independently rather than presenting the model as a binary security guarantee.

The evaluation records:

- accuracy
- precision
- recall
- F1
- false-positive rate
- false-negative rate
- latency distribution

### Why

Security evaluation is more useful when failures are visible.

In particular, the false-negative rate is architecturally important because a missed injection demonstrates why detection cannot be the sole authorization mechanism.

### Consequence

Evaluation results influence architectural reasoning rather than being used only as a headline benchmark number.

A model score is evidence about the detector.

It is not evidence that the entire authorization system is secure.

## 15. Known Security Limitation: Scope-Compliant Injections

### Context

Sentinel can detect many prompt-injection patterns, but detection remains probabilistic.

### Decision

The system explicitly acknowledges the following failure mode:

```text
Injection
   |
   v
Detector misses it
   |
   v
Agent proposes an action
   |
   v
Action is still within authorized category/budget
   |
   v
PolicyGate may allow
```

### Why

The deterministic PolicyGate can enforce the constraints it knows about.

It cannot infer malicious intent that is invisible to the policy inputs.

### Consequence

This creates clear future engineering directions:

- action-intent validation
- stronger semantic policy checks
- domain-specific detector fine-tuning
- specialized document and indirect-injection detection
- richer provenance signals
- stronger authorization semantics

The current architecture therefore reduces the impact of prompt injection without claiming to make malicious intent impossible.

## 16. Current Implementation vs. Production Evolution

The following distinction is intentional.

### Current Sentinel implementation

- deterministic InspectionRouter
- probabilistic prompt-injection detector
- provenance and content hashing
- provenance-scoped inspection cache
- structured ActionProposal
- SHA-256 action fingerprint
- deterministic PolicyGate
- explicit TaskScope
- gate-issued authorization token
- execution-time authorization verification
- in-memory audit logging
- simulated execution
- TXT / Markdown / PDF ingestion

### Production evolution

Areas that would require further engineering include:

- authenticated authorization identity
- cryptographically signed distributed capabilities
- replay protection
- durable audit storage
- production payment-provider integration
- persistent security telemetry
- richer action-intent validation
- stronger document and indirect-injection detectors
- domain-specific detector fine-tuning
- expanded secure web ingestion
- distributed state and cache management

These are not presented as current capabilities. They are the next engineering layers required to operate the architecture in a production environment.

## 17. Engineering Principle

The central architectural decision behind Sentinel is:

> Probabilistic models identify risk; deterministic systems decide authority.

The detector answers a risk question:

> "Does this content show evidence of prompt injection?"

The PolicyGate answers an authorization question:

> "Does this proposed action satisfy the explicit rules and delegated scope?"

The Executor answers an execution-integrity question:

> "Does this execution request exactly match the action that the trusted PolicyGate authorized?"

These decisions are related, but they are not interchangeable.

A detector result can influence the policy decision — for example, a detected injection can escalate an otherwise auto-approvable purchase to REVIEW — but the detector itself never grants execution authority.

The PolicyGate remains the authorization boundary, and the Executor independently verifies that an action reaching execution matches the authorization issued for it.

Keeping risk detection, authorization, and execution integrity as separate responsibilities is the foundation of Sentinel's security boundary.

The objective is not to make the model perfectly trustworthy.

The objective is to design the surrounding system so that model uncertainty does not automatically become execution authority.