# Iron `did:cel` Agents, Services, and Storage

An experimental, modular, composable implementation of an Oblivious Witness Service and `did:cel` identifiers managed by Google Cloud KMS.

This repository provides services, agents, and libraries for creating, managing, witnessing, and verifying `did:cel` event logs in a secure and privacy-preserving way.


## 🛡️ Oblivious Witness Service

Performs oblivious witnessing of event log. Issues signed and timestamped attestations over event log hashes using Google Cloud KMS in a serverless environment. Processes only cryptographic hashes and never accesses event log contents, preserving privacy while producing verifiable W3C VC Data Integrity witness proofs. 

⚡ $O(1)$ c14n, supports RDFC or JCS ⚡

⚛️ Post-Quantum algorithms

🛸 Public Endpoints: 
  - `ecdsa-jcs-2019`, `us-central1`, `HSM`
  - `eddsa-rdfc-2022`, `europe-west1`
  - `mldsa44-jcs-2024`, `us-east4`, ⚛️

Can be used independently of the `did:cel` ecosystem.

👉 See [Iron Witness Service](witness-service/README.md)

## 🔐 Managed `did:cel` Identifiers

A modular suite for managing the lifecycle of secure `did:cel` identifiers using Google Cloud KMS. Components can be used independently or as a unified stack.

### 🧩 Services

- [Provisioning Service](provision-service/README.md) 
  Provisions a `did:cel` DID document by binding existing KMS keys, and initializes the corresponding event log.

- [Heartbeat Service](heartbeat-service/README.md)
  Generates periodic events to ensure liveness and temporal continuity of the event log.
  
- [Update Service](update-service/README.md)
  Handles controlled updates to `did:cel` event logs.

- [Storage Service](storage-service/README.md)
  Utilizes the GCS back-end for the logs as `CelStorageService`. 

- [`CelStorageService` Mirror Github Action](storage-service/did-log-mirror-action.yml)
  Syncs the event logs from GCS or any HTTP endpoint for the `did:cel` identifiers defined in the GitHub repository effectively turning GitHub into a `CelStorageService`.

- **Life-Cycle Listener**
  Reflects changes on KMS keys bound to `did:cel` in the event log (TBD).
  
### ⚙️ Agents

- [Identity Agent](identity-agent/README.md)
  Authorizes operations and proves `did:cel` ownership on behalf of the controller.

- **Activation Agent**
  Orchestrates the setup of a fully operational `did:cel` identifier by coordinating provisioning, persistence, witnessing, and heartbeat scheduling. Ensures the identifier is live, persisted, and witnessed.
  
- [Witness Agent](witness-agent/README.md)
  Orchestrates the oblivious witnessing process for identifiers, using GCS as the event log storage.
  

### 📦 Libraries

- [Resolver](resolver/README.md)
  Resolves `did:cel` identifiers and validates the event log to assemble the DID Document (TBD).
    
- [Witness Verifier](witness-verifier/README.md)
  Library for $O(1)$ verification of W3C VC Data Integrity witness proofs.
  
- **KMS Cryptosuites**

- **CEL Commons**

## 🤝 Contributing

Contributions of all kinds are welcome - whether it’s code, documentation, testing, or community support! Please open PR or issue to get started.

## 📚 Resources

- [The `did:cel` Method Specification](https://w3c-ccg.github.io/did-cel-spec/)
- [W3C Verifiable Credential Data Integrity](https://www.w3.org/TR/vc-data-integrity)
- [Quantum-Safe Cryptosuites](https://w3c-ccg.github.io/di-quantum-safe/)

## 💼 Commercial Support

Commercial support and consulting are available.
For inquiries, please contact: filip26@gmail.com

