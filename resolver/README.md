
_The `did:cel` resolution, the read method is unofficial and provided for experimental purposes._

## Resolution (Read)

The resolution of a `did:cel` identifier is the process of retrieving and validating its event log to produce a compliant DID Document. This method is self-certifying and registry-agnostic, relying on the cryptographic integrity of the log's inception.

### Hybrid Discovery
The `did:cel` method supports a hybrid discovery model. While the `storage` parameter provides a high-performance, deterministic path for resolution, it does not represent a centralized point of failure, the identity is content-addressable, the same log can be hosted across multiple providers, peer-to-peer networks. 

### Algorithm
To resolve a `did:cel` identifier, a resolver MUST perform the following steps:

1. Extract the Commitment: Parse the `method-specific-id = multibase(base58btc, initialDidDocumentHash)` from the `did:cel` to obtain `initialDidDocumentHash`. 
2. Locate the Log: Retrieve the Event Log array from a distributed registry or a location specified by the `storage` parameter. If a `storage` URL is provided, the resolver MAY fetch the resource at `[URL][method-specific-id]`.
3. Verify Inception:
   1. Extract the create event log entry.
   2. Extract `didDocument` from the create event.
   3. The `didDocument.id` and `didDocument.assertionMethod.controller` fields MUST exactly match the `did:cel` which is being resolved.
   4. Recreate `initialDidDocument` by removing the `id` and `assertionMethod.controller` fields from the `didDocument`
   5. Perform `multihash(sha3-256(JCS(initialDidDocument)))`. The result value MUST exactly match the `initialDidDocumentHash` extracted from the DID.
5. Verify Integrity: Iterate through subsequent events ($E_n \dots E_0$), in reverse chronological order, starting with the newest entry, allowing previous verification to be reused if already cached or computed as needed. For each event, verify that:
    - For $E_n$ where $n \gt 1$, the `previousEventHash` MUST match the `sha3-256` hash of the previous event's document hash.
    - The event is signed by a key authorized in the state established by the previous event.
    - Witness Verification: The resolver MUST verify that the event contains a sufficient number of valid witness signatures. The specific threshold and selection of required witnesses are determined by application-level logic based on the trust requirements of the relying party.
6. Verify Liveness & Temporal Continuity: The resolver MUST verify a contiguous chain of heartbeat proofs throughout the log duration. 
    - Liveness: The last event log MUST occur within the period defined in the last effective `didDocument.heartbeatFrequency`.
    - Continuity: Any gap in the heartbeat chain that exceeds the allowed threshold—without an accompanying deactivation or authorized suspension event—MUST result in a validation failure. This ensures that a storage provider cannot omit intermediate events or "freeze" the state in the past.
7. Project State: Apply the cumulative state changes defined in the verified log to construct the final DID Document.
8. Verify Origin: 
    - If the event log was retrieved by using a provided `storage` URL parameter, then that exact URL MUST be listed as an approved `CelStorageService` within the service section of the assembled DID Document.

### Immutability and Caching

The `did:cel` event log is a cryptographically immutable ledger. Because each event $E_n$ is linked via the hash of its predecessor $E_{n-1}$, the log functions as a tamper-evident chain. 

Resolvers SHOULD cache verified events, event logs, locally. Once an event is validated against the inception commitment and the chain of signatures, it never needs to be re-verified or re-fetched.

### `storage`, `CelStorageService`, and URL Construction

The `did:cel` resolver uses a simple string concatenation rule to find logs. The final fetch URL is formed by appending the `method-specific-id` directly to the storage URL.

**Examples**

Path-Based (Static Hosting):
  * `storage`: `https://storage.googleapis.com/did-cel-log/`
  * URL: `https://storage.googleapis.com/did-cel-log/zW1b...`

Query-Based (Dynamic API):
  * `storage`: `https://example/didcel?msid=`
  * URL: `https://example/didcel?msid=zW1b...`

Native IPFS (Content-Addressable):
  * `storage`: `ipfs://bafybeigdy.../`
  * URL: `ipfs://bafybeigdy.../zW1b...`

#### DID URL Parameter

* **Key:** `storage`
* **Value:** A valid URI (typically `https://...`) pointing to a directory or service.
* **Resolution Rule:** The resolver appends the `method-specific-id` to the `storage` value to form the final fetch URL.

---

# Protocol Specification for Key Recovery and Rotation

The following architecture utilizes a pre-rotation commitment scheme to secure an append-only log against assertion key compromise.

---

## Log Entry Data Structure

Each event $E_{n}$ in the log must contain the following fields:

* Sequence Number: $n$
* Previous Event Hash: $H(E_{n-1})$
* Current Assertion Public Key: $K_{a,n}$
* Next Assertion Key Commitment: $H(K_{a,n+1})$
* Recovery Key Commitment: $H(K_{r,current})$
* Next Recovery Key Commitment: $H(K_{r,next})$
* Signature: $\sigma_{a,n}$ (Signed by $K_{a,n}$)



---

## Secure Recovery Solution: The Fork-Resolution Rule

To address the compromise of $K_{a}$, the protocol must implement a recovery event ($E_{rec}$) that supersedes any fraudulent entries.

### 1. Revelation and Validation
When a compromise is detected, the controller issues $E_{rec}$ signed by $K_{r}$. This event must reveal the public key $K_{r}$ that matches the commitment $H(K_{r,current})$ stored in the last uncompromised event $E_{n}$.

### 2. Fork Precedence
The protocol rules for log validators must state:
If two valid events exist for sequence $n+1$, an event signed by $K_{r}$ (Recovery) always invalidates and replaces an event signed by $K_{a}$ (Assertion). 

### 3. State Resynchronization
The recovery event $E_{rec}$ performs the following:
* Invalidates all events signed by the compromised $K_{a}$ at sequence $n+1$ and higher.
* Establishes a new assertion key $K_{a,n+1}'$.
* Establishes a new next-key commitment $H(K_{a,n+2}')$.

---

## Recovery Key Update Policy

The recovery key is the root of trust for the identifier. Its management policy must be distinct from the assertion key to prevent total account takeover.

### 1. Independent Rotation
Rotation of $K_{r}$ should never be permissible via a signature from $K_{a}$ alone. An update to the recovery key commitment ($H(K_{r,next})$) requires a signature from the current $K_{r}$.

### 2. Multi-Signature or Threshold Requirements
For high-security implementations, $K_{r}$ should represent an $M$-of-$N$ threshold. This prevents a single point of failure. The commitment in the log would be the hash of the threshold policy and the set of public keys.

### 3. Cold Storage Constraint
The recovery key must remain offline. The policy should dictate that $K_{r}$ is only loaded into an execution environment during:
* Recovery from $K_{a}$ compromise.
* Scheduled periodic rotation of the recovery key itself.

### 4. Rotation Event Structure
An event updating $K_{r}$ to $K_{r,new}$ must include:
* Revelation of $K_{r,old}$ to satisfy the previous commitment $H(K_{r,old})$.
* Signature $\sigma_{r,old}$ verifying the change.
* New commitment $H(K_{r,new})$ for the subsequent recovery state.

---

## Conflict Resolution Logic

When a validator receives the log, it must process events in sequence. If a recovery signature is encountered:
1.  Verify $K_{r}$ against the commitment in $E_{n-1}$.
2.  Truncate the log at $E_{n-1}$.
3.  Append the recovery event $E_{rec}$ as the new $E_{n}$.
4.  Reject any subsequent attempts to re-attach the compromised branch signed by the old $K_{a}$.

Key pre-rotation is the mechanism that prevents an attacker from taking permanent control of an identifier even if they successfully steal the current assertion key. It functions as a cryptographic "one-way track" that ensures only the legitimate controller can move the identity forward to a new state.

---

## The Window of Vulnerability

In a standard key-value architecture without pre-rotation, if an attacker compromises the current assertion key $K_{a,n}$, they can immediately issue a rotation event to a new key $K_{a,n+1}$ that they fully control. Once this rotation is accepted by the log, the original owner is locked out, and the identifier is permanently hijacked.

Pre-rotation eliminates this window by requiring the controller to commit to the next key before it is ever used or placed online.



---

## Implementation within the Append-Only Log

Pre-rotation fits into the log structure by decoupling the *use* of a key from its *authorization*.

### 1. The Commitment Phase
In event $E_{n}$, the controller signs with $K_{a,n}$. Inside the body of $E_{n}$, they include $H(K_{a,n+1})$. 
* The actual public key $K_{a,n+1}$ is not revealed.
* The private key for $K_{a,n+1}$ is kept in cold storage or a hardware security module (HSM).

### 2. The Revelation/Rotation Phase
When the controller needs to rotate to $E_{n+1}$:
* They reveal $K_{a,n+1}$.
* The log validator checks that $Hash(K_{a,n+1}) == H(K_{a,n+1})$ (the commitment from $E_{n}$).
* The event $E_{n+1}$ is signed by $K_{a,n+1}$.
* A new commitment for the subsequent key $H(K_{a,n+2})$ is provided.

---

## Interaction with Recovery Keys

Pre-rotation and recovery keys work in tandem to create a defense-in-depth strategy:

* Limiting Attacker Scope: If an attacker steals $K_{a,n}$, they can sign fraudulent data at sequence $n$, but they cannot rotate the identifier to a new key. They do not have the private key corresponding to the pre-committed hash $H(K_{a,n+1})$. They are "stuck" at the current sequence.
* The Recovery Leap: While the attacker is trapped at sequence $n$ because they cannot satisfy the pre-rotation commitment, the legitimate owner uses the recovery key $K_{r}$. 
* Overriding Commitments: A recovery event signed by $K_{r}$ has the authority to ignore the previous pre-rotation commitment $H(K_{a,n+1})$ and establish an entirely new branch with a new assertion key and a new pre-rotation commitment.

---

## Security Benefits

| Threat | Outcome with Pre-rotation |
| :--- | :--- |
| Theft of current key $K_{a,n}$ | Attacker can sign as the user but cannot change the key. |
| Server/Database Breach | Public keys are exposed, but next-key secrets remain offline. |
| Quantum Computing | Hash commitments ($H(K)$) are generally more resistant to quantum discovery than active public keys. |

By using pre-rotation, the "ownership" of the identifier is defined not by who holds the current key, but by who holds the secret to the next committed hash.

In your proposed system, should the recovery key also follow a pre-rotation pattern, or is it acceptable for the recovery key to be a static "master" secret kept in physical isolation?

In a production-grade decentralized identity system, the implementation of both mechanisms is required to achieve a resilient security posture. They address distinct failure modes.

---

## Comparative Functional Roles

The following table defines the operational differences between these two mechanisms:

| Feature | Key Rotation (Pre-rotation) | Recovery Key |
| :--- | :--- | :--- |
| Primary Purpose | Proactive risk mitigation and hygiene. | Reactive emergency response. |
| Frequency | Periodic or per-event. | Rare (only upon compromise or loss). |
| Key Exposure | Assertion keys ($K_a$) are "online" or "warm." | Recovery keys ($K_r$) are strictly "cold." |
| Authority Level | Can sign claims and rotate to next $K_a$. | Can override $K_a$ and reset the entire log state. |
| Failure Case | Protects against future theft of $K_a$. | Protects against current theft or loss of $K_a$. |



---

## Why Rotation Alone is Insufficient

If a system only utilizes rotation, even with pre-rotation, it remains vulnerable to "Denial of Control" attacks.

1. Loss of Secret: If the controller loses the private key for the next pre-committed assertion key ($K_{a,n+1}$), they can no longer progress the log. The identifier becomes dead.
2. Race Conditions: If an attacker steals the current key $K_{a,n}$ and the controller does not have a superior recovery key, the attacker can attempt to sign fraudulent data at the current sequence. While pre-rotation prevents the attacker from moving to sequence $n+1$ (assuming they lack the next secret), the legitimate user is also stuck if they cannot "out-sign" the attacker with a higher-privilege key.

---

## Why Recovery Alone is Insufficient

If a system only utilizes a static recovery key without rotation:

1. Cryptographic Attrition: Using the same assertion key $K_{a}$ indefinitely increases the volume of ciphertext available for analysis and the probability of side-channel leaks.
2. Single Point of Failure: The recovery key becomes the only way to update the system. If the recovery key is static and eventually compromised, the entire identifier is permanently lost because there is no mechanism to "rotate" the root of trust itself.

---

## The Integrated Architecture

The most secure approach integrates both into a tiered authority model:

### Tier 1: Assertion Rotation
$K_{a}$ is rotated frequently. Each event $E_{n}$ commits to $H(K_{a,n+1})$. This ensures that if $K_{a,n}$ is leaked, the attacker’s window of utility is limited to the current state. They cannot pivot to the next state because they lack the pre-committed secret.

### Tier 2: Recovery Intervention
$K_{r}$ is held in high-security isolation (e.g., multi-sig, paper backup, or hardware vault). It is only invoked if:
* $K_{a,n}$ is compromised.
* The secret for $H(K_{a,n+1})$ is lost.

In this scenario, $K_{r}$ provides the cryptographic proof to "fork" the log away from the compromised or dead-end branch and establish a new sequence with a fresh $K_{a}$ and a fresh pre-rotation commitment.

---

## Operational Logic for Both

A secure policy dictates:
1. Rotate $K_{a}$ frequently to minimize the impact of a single key leak.
2. Maintain $K_{r}$ as a master authority that can re-anchor the identity if the rotation chain is broken.
3. Periodically rotate $K_{r}$ itself (using the existing $K_{r}$ to authorize the new one) to ensure the recovery material remains viable and has not been silently compromised.

Does the implementation environment require the recovery key to be held by a third-party guardian or solely by the end-user?

# Hybrid Recovery and Rotation Protocol

This architecture supports a flexible recovery model where the recovery authority can be satisfied by the end-user, a set of guardians, or a combination of both.

---

## Unified Recovery Commitment

The log entry $E_n$ commits to a recovery policy rather than a single static key. This allows for the "both is possible" scenario by using a threshold structure.

### 1. The Commitment Formula
The recovery commitment $H(K_{r,policy})$ represents the hash of a policy $P$. This policy $P$ defines:
* The set of public keys $\{K_{r,1}, K_{r,2}, ... K_{r,m}\}$.
* The threshold requirement $t$ (e.g., 2-of-3).

### 2. Participant Composition
The set of keys can be distributed as follows:
* $K_{r,1}$: End-user cold storage (e.g., a hardware device or paper mnemonic).
* $K_{r,2}$: A trusted third-party guardian (e.g., a professional recovery service).
* $K_{r,3}$: A secondary personal device or a social contact.



---

## Recovery Workflow for Hybrid Environments

The protocol handles recovery through a revelation of the policy and a threshold signature.

### Phase 1: Policy Revelation
To initiate recovery, the initiator must publish the full policy $P$ that was previously hashed in the log. Validators verify that $Hash(P) == H(K_{r,policy})$.

### Phase 2: Threshold Authorization
The recovery event $E_{rec}$ must be signed by a number of keys equal to or greater than $t$.
* Case A (Self-Sovereign): The user provides signatures from their own partitioned keys (e.g., $K_{r,1}$ and $K_{r,3}$).
* Case B (Delegated): The user provides their signature $K_{r,1}$ and requests a signature from the third-party guardian $K_{r,2}$.

---

## Technical Comparison of Recovery Scenarios

| Feature | Self-Custody Recovery | Guardian-Assisted Recovery |
| :--- | :--- | :--- |
| Initiation | User alone | User + Third Party |
| Privacy | High (No external knowledge) | Moderate (Guardian knows ID exists) |
| Availability | Subject to user's backup habits | Higher (Guardian provides redundancy) |
| Protocol Path | Single recovery signature | Multi-signature or Threshold Sig |

---

## Security Policy for Recovery Key Rotation

Because the recovery policy is the ultimate root of authority, its rotation must be handled with higher friction than standard assertion key rotation.

### 1. Mandatory Pre-Rotation for Recovery
Every recovery event $E_{rec}$ must include a commitment to the next recovery policy $H(K_{r,policy,next})$. This prevents an attacker who manages to compromise the current threshold from maintaining control indefinitely.

### 2. Time-Locked Recovery (Optional)
To prevent "ninja" recoveries by a compromised guardian, the protocol can implement a sequence-lock or time-lock.
* A recovery event is submitted to the log.
* A waiting period (e.g., 24 hours) begins.
* During this period, the current assertion key $K_a$ (if not compromised) can issue a "cancellation" event to abort the recovery.

### 3. Verification Logic
Validators must only accept $E_{rec}$ if:
1. It references a valid sequence number $n$ in the existing log.
2. It provides the pre-image (Policy $P$) for the recovery commitment in $E_{n-1}$.
3. It contains $t$ valid signatures according to $P$.



---

## Interaction with Assertion Pre-Rotation

In this system:
* Assertion keys ($K_a$) use pre-rotation for per-event hygiene.
* Recovery keys ($K_r$) provide a multi-sig safety net for assertion key compromise or loss.
* The recovery event overwrites the assertion pre-rotation commitment, allowing the user to "jump" to a new, secure state regardless of the previous $H(K_{a,n+1})$.

This configuration ensures that neither a single key theft nor a single lost device results in the loss of the identifier.
