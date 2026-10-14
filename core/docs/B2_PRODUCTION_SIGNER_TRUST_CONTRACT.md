# B2 Production Signer Trust Foundation Contract

This document records the R1 signer, trust, and production signer admission foundation implemented for Phase B2. It is a contract foundation only. It does not provision a real production private key, does not create production trust, does not create a real Signed Migration Intent, and does not execute Production GENESIS.

## Owner policy binding

The R1 production signer contract is Ed25519. The R1 production signer provider is an encrypted file-backed Ed25519 provider behind a `SignerProvider` abstraction. The encrypted private-key file is expected to live on D-backed Qingyu protected storage with OWNER_ONLY / POSIX 0600-equivalent semantics. The signer passphrase is a dedicated high-entropy secret separate from database, GitHub, and backup-recovery credentials.

The production signer is exportable for owner custody and disaster recovery. Secondary signer-key custody and offline recovery remain mandatory gates before GENESIS. Full signer/trust rotation is deferred after R1, while the TrustRecord generation/status fields preserve the rotation path.

## Provider contract

A signer provider exposes only public operational metadata: provider reference, backend type, classification, algorithm, key id, public key, signing operation, and readiness metadata. It must not expose raw private-key bytes or passphrase values through model fields, signatures, trust records, admission records, or readiness metadata.

Provider classifications remain descriptive metadata:

- `TEST_ONLY`
- `REHEARSAL_ONLY`
- `SYNTHETIC_PRODUCTION_TEST_ONLY`
- `PRODUCTION_ELIGIBLE`

Classification is not admission. A provider self-asserting `PRODUCTION_ELIGIBLE` does not prove production custody and does not authorize REAL_PRODUCTION use.

## Production signer admission

REAL_PRODUCTION requires a `ProductionSignerAdmissionRecord` resolved from a `ProductionSignerAdmissionStore`. The admission record is an owner/provisioning-controlled assertion, not data supplied by a Signed Migration Intent, TrustRecord creation, ordinary activation request, or provider metadata.

The admission record binds schema version, admission reference, provider reference, provider backend type, algorithm, key id, public key fingerprint, environment, target reference, storage policy, permission policy, custody policy version, provisioning reference, provisioning generation, status, and created metadata. It contains no private key, passphrase, or recovery secret.

For R1, the only approved production backend is `encrypted-file-backed-ed25519`, implemented by `EncryptedFileBackedEd25519SignerProvider`. `InMemoryEd25519SignerProvider` is never production eligible, including when mislabeled `PRODUCTION_ELIGIBLE`.

## Trust record contract

A trust record binds the signer public key to a target and environment. It records schema version, trust reference, algorithm, key id, raw Ed25519 public key, public key fingerprint, provider reference, provider backend type, environment, target reference, generation, creation time, status, provider classification, and rotation-deferred marker.

The key id and public key fingerprint are both derived from the Ed25519 raw public key using the existing R1 key id function. Mismatches fail closed.

## Signed Migration Intent verification

Signed Migration Intent verification now requires:

- a trust store containing the referenced trust record;
- Ed25519 signer algorithm;
- `signer_key_id` equal to the trust record key id;
- trust environment equal to intent target environment;
- trust target reference equal to intent target reference;
- optional target contract binding equal to the intent environment and target;
- environment-mode production eligibility guard;
- REAL_PRODUCTION admission verification when applicable;
- a valid Ed25519 signature over canonical Signed Migration Intent payload bytes with the R1 SMI signature domain.

Missing trust, revoked trust, retired trust, malformed signature, unknown trust, wrong key id, wrong environment, wrong target, missing admission, inactive admission, backend mismatch, storage/permission mismatch, and invalid signature all fail before durable production-authority mutation.

## Production Authority binding

Production Authority candidate validation consumes the same side-effect-free activation validator used by read-only plan construction. It receives the trust store, environment mode, optional admission store, and optional signer provider, verifies the Signed Migration Intent against trust material and admission when applicable, and persists the authority trust binding into durable candidate rows: algorithm, key id, public key fingerprint, trust schema version, trust environment, and trust target reference.

On restart or continuation, the current resolved TrustRecord is explicitly compared against the persisted trust binding. Drift fails closed with `B2_PERSISTED_TRUST_BINDING_MISMATCH`.

Audit rows carry the non-secret signer identity fields directly so historical signer evidence does not depend only on current active trust resolution.

This is a foundation for future real production authority provisioning. It is not a claim that signer/trust/admission provisioning, PRE_ACTIVATION_READY, B2 completion, Phase B completion, or Production GENESIS has occurred.
