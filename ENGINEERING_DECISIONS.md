# Engineering Decisions

This document records the significant engineering decisions made while building Sentinel. It explains the reasoning behind the architecture, the alternatives considered, and the trade-offs that remain.

It provides context beyond the source code and explains the engineering reasoning behind the system.

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

The resulting architecture is built around one principle:

> **Untrusted content may influence agent reasoning, but it cannot independently grant execution authority.**

---

## 1. Separate Detection from Authorization

Prompt-injection detection and authorization answer different security questions.

A detector is probabilistic. It produces a label and confidence score and can be wrong in either direction. Authorization, on the other hand, has explicit constraints such as spending limits, allowed categories, and delegated task scope.

Sentinel therefore does not allow the detector to become the authorization authority.

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

The detector answers:

> "Does this content show evidence of prompt injection?"

The PolicyGate answers:

> "Does this proposed action satisfy the explicit authorization policy?"

These are related decisions, but they are not interchangeable.

A detector result is therefore treated as security evidence, not as an authorization credential.

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

A detector SAFE result means only that the model did not classify the content as an injection. It does not mean that the resulting action is authorized.

The reverse is also important: when the detector identifies an injection, that result can influence policy. In the current implementation, a detected injection prevents an otherwise auto-approvable action from receiving ALLOW and routes it to REVIEW.

This separation means that improving detector accuracy improves the inspection layer, but does not remove the need for deterministic authorization.

### Known boundary

A detector false negative cannot be treated as equivalent to a secure result.

If an injection is missed and the resulting action nevertheless remains within the explicitly authorized category and spending constraints, the PolicyGate may still allow it.

This is a deliberate architectural limitation rather than something hidden behind the detector's confidence score.

## 2. Use Deterministic Policy Enforcement for Financial Authorization

Financial authorization has a bounded decision space. Sentinel needs to enforce spending limits, category restrictions, task scope, and escalation rules consistently.

The PolicyGate therefore uses deterministic rules rather than asking an LLM to decide whether an action should be authorized.

The current spending policy is:

| Condition | Decision |
|---|---|
| Amount <= ₹5,000 | ALLOW, subject to authorization checks |
| ₹5,000 < Amount <= ₹50,000 | REVIEW |
| Amount > ₹50,000 | DENY |

Additional checks include:

- requested category must match the authorized category
- optional maximum budget must not be exceeded
- a detector injection flag prevents automatic ALLOW and routes the action to REVIEW
- an ALLOW decision must contain a valid gate-issued authorization token

The policy layer is deliberately explicit because these conditions are already representable as deterministic security rules.

This provides:

- predictable behavior
- explicit security boundaries
- reproducible decisions
- straightforward testing
- auditable authorization logic

An LLM could be useful for interpreting ambiguous natural-language intent, but the final spending authorization should not depend on probabilistic model behavior.

### Why not use an LLM as the authorization authority?

The current authorization conditions are already expressible as explicit rules. Using an LLM as the final authority would make a security-critical decision dependent on probabilistic model behavior without providing a corresponding benefit for the current policy space.

The trade-off is that the policy layer does not independently understand arbitrary natural-language intent. Its strength is that once an action has been represented structurally, its authorization decision is deterministic and reproducible.

## 3. Route Inspection Before Model Inference

Not every request requires full ML-based inspection.

Some requests can be rejected through deterministic checks, while previously inspected content may be eligible for cache reuse. Running the detector for every request would also make the model an unnecessary mandatory dependency.

All `/scan` requests therefore pass through the InspectionRouter.

The router can produce:

- `BLOCK`
- `CACHE_REUSE`
- `DEEP_INSPECT`

Its decision is based on:

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

This creates a deterministic control point before probabilistic inference.

The router can reject invalid inputs early, reuse trusted inspection observations where appropriate, and invoke the detector only when deeper inspection is required.

The detector is therefore no longer responsible for every request path.

The router itself becomes part of the security boundary and must remain deterministic and auditable.

## 4. Establish Content Identity, Provenance, and Safe Inspection Reuse

Inspection results are only meaningful if the system knows which content was actually inspected.

A cached detector result cannot safely be treated as globally reusable for arbitrary content. Two pieces of content may look similar while being different security inputs.

Sentinel establishes a canonical representation of ingested content, computes a SHA-256 content hash, and associates the content with provenance information.

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

The content hash provides a deterministic identity for the content being inspected.

Provenance provides the context in which that content was obtained.

Together they allow Sentinel to distinguish previously inspected content from different content that merely looks similar.

### Inspection state is separate from authorization state

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

This distinction is important because the two pieces of state have different security semantics:

- a detector observation is associated with inspected content
- an authorization decision is associated with a specific action and current authorization context

Caching the first can avoid repeated model inference.

Caching the second could allow an old authorization decision to bypass current policy evaluation.

Therefore:

> Inspection state may be reused when content identity and provenance permit it; authorization remains request-specific.

## 5. Bind Authorization to the Exact Action Being Executed

The agent's desired action should not directly become an executable operation.

Sentinel represents intended actions through an explicit ActionProposal. This creates a structured boundary between agent intent and system permission.

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

ActionProposal validates action-level properties including:

- currency
- quantity
- total amount
- required action fields

It also provides a SHA-256 fingerprint over the security-relevant action fields.

The fingerprint binds authorization to the exact action representation that was evaluated.

For example, suppose an action is authorized as:

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

The important distinction is:

- **PolicyGate:** "Is this action authorized?"
- **Fingerprint:** "Is this still the exact action that was authorized?"
- **Executor:** "Does the execution request match the authorization?"

The fingerprint is not a replacement for spending-policy enforcement.

If an action is already ₹40,000 and the configured policy does not permit it, the PolicyGate must reject or escalate it according to the policy.

The fingerprint protects against a different failure mode: an action being modified after authorization.

### Keep the Executor non-authoritative

The Executor does not independently decide whether an action should be allowed.

It verifies that the execution request corresponds to a valid ALLOW decision and checks:

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

The PolicyGate is the authorization authority.

The Executor is responsible for enforcing the output of that authority and verifying that the action reaching execution still matches what was authorized.

This creates one explicit authorization path rather than multiple components independently deciding whether execution is permitted.

## 6. Represent Delegated Authorization Explicitly

An action must be evaluated against what the user has actually authorized the agent to do.

Sentinel represents this authorization context through TaskScope.

TaskScope contains the information used by the PolicyGate to evaluate:

- allowed category
- maximum authorized budget
- task scope requirements

This makes authorization explicit rather than requiring the policy layer to infer authority from the agent's natural-language reasoning.

It also makes the policy decision inspectable and testable.

### Current implementation boundary

The current implementation supplies TaskScope through the prototype request boundary.

It is not independently authenticated.

It is an explicit authorization context consumed by the policy layer, but the surrounding identity and integrity mechanism required to establish that context securely is outside the current implementation.

The current authorization handoff also uses an in-process gate-issued token. The Executor verifies that the authorization information corresponds to the expected request and action fingerprint.

This provides an explicit capability handoff between the PolicyGate and Executor within the current implementation.

### Production evolution

A production deployment would derive the authorization context from an authenticated and integrity-protected identity/capability layer rather than trusting a request-supplied authorization object.

The capability mechanism would also need stronger semantics, including mechanisms such as:

- cryptographically signed capabilities
- explicit capability scope
- expiration
- nonce or replay protection
- distributed verification
- authenticated principal identity
- durable audit storage

These are production evolution paths rather than capabilities claimed by the current implementation.

## 7. Fail Closed on Security-Critical Inspection Errors

A detector failure must not silently become equivalent to a SAFE classification.

Sentinel therefore fails closed when prompt-injection model inference encounters an error.

The system does not convert an inspection failure into a successful safety result.

There is an important distinction between:

```text
SAFE
```

and:

```text
UNAVAILABLE
```

Treating both as SAFE would convert an availability failure into a security failure.

The consequence is that inspection failures can reduce availability, but they do not silently weaken the security boundary.

## 8. Use a Fixed Detector and Evaluate Its Limitations

Sentinel currently uses the locked pretrained model:

```text
protectai/deberta-v3-base-prompt-injection-v2
```

with a fixed threshold of 0.5.

The detector is intentionally kept fixed rather than fine-tuned as part of the current implementation.

This makes the evaluation reproducible and makes it possible to distinguish:

- changes to the detection model
- changes to the surrounding security architecture

The detector's output remains probabilistic evidence rather than an authorization credential.

### Evaluation

Sentinel evaluates the detector using a frozen benchmark containing:

- 240 examples
- 120 SAFE
- 120 INJECTION
- fixed detector configuration
- fixed threshold

The evaluation records:

- accuracy
- precision
- recall
- F1
- false-positive rate
- false-negative rate
- latency distribution

The benchmark produced:

| Metric | Result |
|---|---|
| Accuracy | 81.25% |
| Precision | 88.66% |
| Recall | 71.67% |
| F1 | 79.26% |
| False-positive rate | 9.17% |
| False-negative rate | 28.33% |
| Minimum latency | 6.52 ms |
| Mean latency | 285.67 ms |
| Median latency | 289.25 ms |
| P95 latency | 361.17 ms |
| Maximum latency | 463.48 ms |

The false-negative rate is particularly important architecturally.

A missed injection demonstrates why detection cannot be the sole authorization mechanism.

The benchmark also exposed weaker performance on indirect and document-oriented injection patterns. That limitation directly informs the surrounding architecture and future work.

### Future detector improvement

A Sentinel-specific detector could eventually be fine-tuned on a domain-specific dataset containing:

- direct prompt injections
- indirect prompt injections
- document-borne injections
- web-content injections
- commerce-specific manipulation attempts
- benign financial instructions
- hard negatives
- adversarially constructed examples

A potential training and evaluation pipeline would be:

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

## 9. Known Security Limitation: Scope-Compliant Injections

Sentinel explicitly acknowledges a failure mode that deterministic authorization cannot solve by itself.

Consider:

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

The PolicyGate can enforce the constraints it knows about.

It cannot infer malicious intent that is invisible to the policy inputs.

For example, if an injection causes the agent to choose an action that is still within the user's explicitly authorized category and budget, and the detector fails to identify the injection, the deterministic policy may have no rule that distinguishes the resulting action from a legitimate one.

This is why Sentinel's security boundary is not presented as "the detector catches every attack."

The architecture instead limits what a missed injection can authorize by requiring the resulting action to satisfy explicit authorization constraints.

### Future engineering directions

The main directions exposed by this limitation are:

- action-intent validation
- stronger semantic policy checks
- domain-specific detector fine-tuning
- specialized document and indirect-injection detection
- richer provenance signals
- stronger authorization semantics

The current architecture therefore reduces the impact of prompt injection without claiming to make malicious intent impossible.

## 10. Engineering Principle

The central architectural principle behind Sentinel is:

> Probabilistic models identify risk; deterministic systems decide authority.

The system separates three responsibilities:

- **Detector:** identifies evidence of prompt injection.
- **PolicyGate:** determines whether the proposed action satisfies explicit authorization policy.
- **Executor:** verifies that the action reaching execution matches the authorization issued for it.

A detector result can influence the policy decision, but the detector itself never grants execution authority.

The PolicyGate remains the authorization boundary, while the Executor verifies the integrity of the authorization-to-execution handoff.

The objective is not to make the model perfectly trustworthy.

The objective is to ensure that model uncertainty does not automatically become execution authority.