# `did:cel` Identity Agent

A service that acts on behalf of a DID controller to prove DID ownership.  

It supports:

- Receiving requests tied to a DID.
- Optionally waiting for user approval on mobile.
- Producing verifiable proofs (VCDI) that assert control of the DID.
- Acting as a delegated identity agent across authentication, consent, and other flows.

This agent enables applications to securely verify DID control while respecting user approval and delegation.
