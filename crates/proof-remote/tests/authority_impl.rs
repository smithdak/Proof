//! Integration tests for the `proof-remote` authority module.
//!
//! These exercise the retained remote-authority DSSE vector, the closed
//! 15-variant payload union, strict canonicalization/digest production,
//! one-signature Ed25519 signing/verification, tamper and bound rejection, and
//! the causal chain validator.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use proof_attestation::{Ed25519SigningProvider, ProofSigningProvider as _};
use proof_canonical::canonicalize;
use proof_domain::{ContentDigest, Timestamp};
use proof_remote::{
    AuthorityHeadV1, RemoteAuthorityRecordV1, RemoteError, VerifiedRemoteAuthorityRecord,
    WorkspaceRole, WorkspaceRoleAssignmentV1,
    authority::{
        ActiveAuthorityKeyResolver, MAX_REMOTE_AUTHORITY_ENVELOPE_BYTES,
        MAX_REMOTE_AUTHORITY_PAYLOAD_BYTES, REMOTE_AUTHORITY_RECORD_DIGEST_CONTEXT,
        WorkspaceRoleAssignmentApiVersion, parse_remote_authority_record_envelope,
        remote_authority_pae, sign_remote_authority_record, validate_chain,
        verify_remote_authority_record_envelope,
    },
};

/// Deterministic single-byte pattern digest helper.
fn cd(byte: u8) -> ContentDigest {
    ContentDigest::blake3([byte; 32])
}

fn ts() -> Timestamp {
    "2026-08-23T01:00:00Z".parse().unwrap()
}

fn head(sequence: u64, digest: ContentDigest) -> AuthorityHeadV1 {
    AuthorityHeadV1 {
        sequence,
        record_digest: digest,
    }
}

/// Canonical bytes of a `DsseEnvelope` (used to build tampered envelopes).
fn canonical_envelope(envelope: &proof_attestation::DsseEnvelope) -> Vec<u8> {
    canonicalize(&serde_json::to_value(envelope).unwrap())
        .unwrap()
        .as_bytes()
        .to_vec()
}

fn hex_decode(encoded: &str) -> Vec<u8> {
    assert_eq!(encoded.len() % 2, 0);
    (0..encoded.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&encoded[index..index + 2], 16).unwrap())
        .collect()
}

/// A single-key resolver used to prove the active-Workspace-key rule.
struct FixedResolver {
    active_key_id: String,
    active_public_key: [u8; 32],
}

impl ActiveAuthorityKeyResolver for FixedResolver {
    fn resolve_active_key(&self, key_id: &str) -> Result<[u8; 32], RemoteError> {
        if key_id == self.active_key_id {
            Ok(self.active_public_key)
        } else {
            Err(RemoteError::Authority(format!(
                "no active authority key `{key_id}`"
            )))
        }
    }
}

fn make_signer(seed: u8) -> (Ed25519SigningProvider, String, [u8; 32]) {
    let signer = Ed25519SigningProvider::from_secret_bytes(&[seed; 32]);
    let metadata = signer.metadata().unwrap();
    let public_key: [u8; 32] = metadata.public_key.as_slice().try_into().unwrap();
    let key_id = metadata.key_id;
    (signer, key_id, public_key)
}

fn variant_name(record: &RemoteAuthorityRecordV1) -> &'static str {
    match record {
        RemoteAuthorityRecordV1::AgentBindingIssue(_) => "agent-binding-issue",
        RemoteAuthorityRecordV1::AgentBindingRevocation(_) => "agent-binding-revocation",
        RemoteAuthorityRecordV1::DelegationIssue(_) => "delegation-issue",
        RemoteAuthorityRecordV1::DelegationRevocation(_) => "delegation-revocation",
        RemoteAuthorityRecordV1::OidcBindingIssue(_) => "oidc-binding-issue",
        RemoteAuthorityRecordV1::OidcBindingRevocation(_) => "oidc-binding-revocation",
        RemoteAuthorityRecordV1::WorkspaceRoleAssignment(_) => "workspace-role-assignment",
        RemoteAuthorityRecordV1::WorkspaceRoleRevocation(_) => "workspace-role-revocation",
        RemoteAuthorityRecordV1::RemotePrincipalStatus(_) => "remote-principal-status",
        RemoteAuthorityRecordV1::ChangeSetApproval(_) => "changeset-approval",
        RemoteAuthorityRecordV1::EnvironmentCreation(_) => "environment-creation",
        RemoteAuthorityRecordV1::EnvironmentConfigProposal(_) => "environment-config-proposal",
        RemoteAuthorityRecordV1::EnvironmentConfigActivation(_) => "environment-config-activation",
        RemoteAuthorityRecordV1::RemoteAuthorizationDecision(_) => "remote-authorization-decision",
        RemoteAuthorityRecordV1::RemoteApplicationConsequence(_) => {
            "remote-application-consequence"
        }
    }
}

/// The 15 closed variants, each bound to its retained conformance vector.
const VARIANTS: [(&str, &[u8]); 15] = [
    (
        "workspace-role-assignment",
        include_bytes!(
            "../../../conformance/v1/collaboration-server/vectors/workspace-role-assignment.valid.json"
        ),
    ),
    (
        "workspace-role-revocation",
        include_bytes!(
            "../../../conformance/v1/collaboration-server/vectors/workspace-role-revocation.valid.json"
        ),
    ),
    (
        "remote-principal-status",
        include_bytes!(
            "../../../conformance/v1/collaboration-server/vectors/remote-principal-status.valid.json"
        ),
    ),
    (
        "oidc-binding-issue",
        include_bytes!(
            "../../../conformance/v1/collaboration-server/vectors/oidc-principal-binding.valid.json"
        ),
    ),
    (
        "oidc-binding-revocation",
        include_bytes!(
            "../../../conformance/v1/collaboration-server/vectors/oidc-principal-binding-revocation.valid.json"
        ),
    ),
    (
        "changeset-approval",
        include_bytes!(
            "../../../conformance/v1/collaboration-server/vectors/changeset-approval.valid.json"
        ),
    ),
    (
        "environment-creation",
        include_bytes!(
            "../../../conformance/v1/collaboration-server/vectors/environment-creation.valid.json"
        ),
    ),
    (
        "environment-config-proposal",
        include_bytes!(
            "../../../conformance/v1/collaboration-server/vectors/environment-config-proposal.valid.json"
        ),
    ),
    (
        "environment-config-activation",
        include_bytes!(
            "../../../conformance/v1/collaboration-server/vectors/environment-config-activation.valid.json"
        ),
    ),
    (
        "remote-authorization-decision",
        include_bytes!(
            "../../../conformance/v1/collaboration-server/vectors/remote-authorization-decision.valid.json"
        ),
    ),
    (
        "remote-application-consequence",
        include_bytes!(
            "../../../conformance/v1/collaboration-server/vectors/remote-application-consequence.valid.json"
        ),
    ),
    (
        "agent-binding-issue",
        include_bytes!("../../../conformance/v1/authority/vectors/principal-binding.valid.json"),
    ),
    (
        "agent-binding-revocation",
        include_bytes!(
            "../../../conformance/v1/authority/vectors/principal-binding-revocation.valid.json"
        ),
    ),
    (
        "delegation-issue",
        include_bytes!("../../../conformance/v1/authority/vectors/delegation-v2.valid.json"),
    ),
    (
        "delegation-revocation",
        include_bytes!(
            "../../../conformance/v1/authority/vectors/delegation-revocation.valid.json"
        ),
    ),
];

#[test]
fn golden_dsse_vector_matches_frozen_manifest() {
    let manifest: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../conformance/v1/collaboration-server/vectors/remote-authority-record.dsse-bytes.valid.json"
    ))
    .unwrap();
    let payload_value: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../conformance/v1/collaboration-server/vectors/workspace-role-assignment.valid.json"
    ))
    .unwrap();
    let record: RemoteAuthorityRecordV1 = serde_json::from_value(payload_value.clone()).unwrap();
    assert!(matches!(
        record,
        RemoteAuthorityRecordV1::WorkspaceRoleAssignment(_)
    ));

    let canonical_payload = canonicalize(&payload_value).unwrap();
    assert_eq!(
        BASE64.encode(canonical_payload.as_bytes()),
        manifest["payload_utf8_base64"].as_str().unwrap()
    );
    assert_eq!(
        BASE64.encode(remote_authority_pae(canonical_payload.as_bytes()).unwrap()),
        manifest["pae_utf8_base64"].as_str().unwrap()
    );
    assert_eq!(
        record.digest().to_string(),
        manifest["payload_digest"].as_str().unwrap()
    );

    let envelope_value: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../conformance/v1/collaboration-server/vectors/remote-authority-record-envelope.valid.json"
    ))
    .unwrap();
    let canonical_envelope = canonicalize(&envelope_value).unwrap();
    let parsed = parse_remote_authority_record_envelope(canonical_envelope.as_bytes()).unwrap();
    assert_eq!(parsed.record, record);
    assert_eq!(
        parsed.envelope_digest.to_string(),
        manifest["envelope_digest"].as_str().unwrap()
    );

    let expected_key_id = manifest["signer"]["key_id"].as_str().unwrap();
    let expected_public_key: [u8; 32] =
        hex_decode(manifest["signer"]["public_key_hex"].as_str().unwrap())
            .try_into()
            .unwrap();
    let verified =
        verify_remote_authority_record_envelope(canonical_envelope.as_bytes(), expected_key_id)
            .unwrap();
    assert_eq!(verified.key_id, expected_key_id);
    assert_eq!(verified.public_key, expected_public_key);
}

#[test]
fn every_variant_round_trips_digest_sign_and_verify() {
    let (signer, key_id, public_key) = make_signer(7);

    for (expected_name, bytes) in VARIANTS {
        let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        let record: RemoteAuthorityRecordV1 = serde_json::from_value(value.clone())
            .unwrap_or_else(|error| panic!("vector `{expected_name}` did not decode: {error}"));
        assert_eq!(
            variant_name(&record),
            expected_name,
            "vector `{expected_name}` must decode to its exact variant"
        );

        // Canonical bytes -> digest round-trips byte-for-byte.
        let canonical = canonicalize(&value).unwrap();
        let reserialized = serde_json::to_value(&record).unwrap();
        assert_eq!(canonicalize(&reserialized).unwrap(), canonical);
        assert_eq!(
            record.digest(),
            proof_remote::derive_key_digest(
                REMOTE_AUTHORITY_RECORD_DIGEST_CONTEXT,
                canonical.as_bytes()
            ),
            "digest must use the exact payload context and canonical bytes"
        );

        // Sign -> strict parse -> verify with the same Ed25519 keypair.
        let signed_envelope = sign_remote_authority_record(&record, &signer).unwrap();
        assert_eq!(signed_envelope.key_id, key_id);
        assert_eq!(signed_envelope.payload_digest, record.digest());
        let parsed =
            parse_remote_authority_record_envelope(signed_envelope.envelope_json.as_bytes())
                .unwrap();
        assert_eq!(parsed.record, record);
        assert_eq!(parsed.payload_json, signed_envelope.payload_json);
        assert_eq!(parsed.envelope_digest, signed_envelope.envelope_digest);

        let verified = verify_remote_authority_record_envelope(
            signed_envelope.envelope_json.as_bytes(),
            &key_id,
        )
        .unwrap();
        assert_eq!(verified.key_id, key_id);
        assert_eq!(verified.public_key, public_key);
        assert_eq!(verified.parsed.record, record);
    }
}

#[test]
fn signature_and_payload_tamper_are_rejected() {
    let (signer, key_id, _) = make_signer(11);
    let record: RemoteAuthorityRecordV1 = serde_json::from_slice(include_bytes!(
        "../../../conformance/v1/collaboration-server/vectors/workspace-role-assignment.valid.json"
    ))
    .unwrap();
    let signed_envelope = sign_remote_authority_record(&record, &signer).unwrap();

    // One-bit signature tamper fails verification.
    let mut tampered_signature = signed_envelope.envelope.clone();
    let mut signature = BASE64
        .decode(&tampered_signature.signatures[0].sig)
        .unwrap();
    signature[0] ^= 1;
    tampered_signature.signatures[0].sig = BASE64.encode(signature);
    assert!(
        verify_remote_authority_record_envelope(&canonical_envelope(&tampered_signature), &key_id,)
            .is_err()
    );

    // One-byte payload tamper fails verification.
    let mut tampered_payload = signed_envelope.envelope.clone();
    let mut payload = BASE64.decode(&tampered_payload.payload).unwrap();
    let mid = payload.len() / 2;
    payload[mid] ^= 1;
    tampered_payload.payload = BASE64.encode(&payload);
    assert!(
        verify_remote_authority_record_envelope(&canonical_envelope(&tampered_payload), &key_id,)
            .is_err()
    );

    // A wrong expected key is rejected even though the envelope is intact.
    let (_, other_key_id, _) = make_signer(12);
    assert!(
        verify_remote_authority_record_envelope(
            signed_envelope.envelope_json.as_bytes(),
            &other_key_id
        )
        .is_err()
    );
}

#[test]
fn payload_and_envelope_maxima_are_rejected() {
    // PAE enforces the payload bound before allocating the PAE.
    assert!(matches!(
        remote_authority_pae(&vec![b'a'; MAX_REMOTE_AUTHORITY_PAYLOAD_BYTES + 1]),
        Err(RemoteError::Authority(_))
    ));
    assert!(remote_authority_pae(&vec![b'a'; MAX_REMOTE_AUTHORITY_PAYLOAD_BYTES]).is_ok());

    // The envelope bound is enforced before any parsing.
    assert!(matches!(
        parse_remote_authority_record_envelope(&vec![
            b' ';
            MAX_REMOTE_AUTHORITY_ENVELOPE_BYTES + 1
        ]),
        Err(RemoteError::Authority(_))
    ));

    // Signing an over-sized canonical payload is rejected.
    let (signer, _, _) = make_signer(13);
    let over_size = serde_json::from_value(serde_json::json!({
        "api_version": "proof.dev/workspace-role-assignment/v1",
        "assigned_at": "2026-08-23T01:30:00Z",
        "assigned_by_actor_context_digest": "blake3:3030303030303030303030303030303030303030303030303030303030303030",
        "assigned_by_principal_id": "019e0000-0000-7000-8000-000000000007",
        "assignment_id": "019e0000-0000-7000-8000-000000000030",
        "authority_key_id": "ed25519:34b4d9043156cb6dcf0beb0a2949b7559c940d2bcb6dbe8c53a9b30278e3a746",
        "authority_sequence": 31,
        "evaluated_authority_head": {
            "record_digest": "blake3:3131313131313131313131313131313131313131313131313131313131313131",
            "sequence": 30
        },
        "previous_authority_record_digest": "blake3:3131313131313131313131313131313131313131313131313131313131313131",
        "principal_id": "019e0000-0000-7000-8000-000000000004",
        "role": "content.reviewer",
        "workspace_id": "019e0000-0000-7000-8000-000000000001"
    }))
    .unwrap();
    let mut over_size = over_size;
    // Expand a free-form string field well past the payload maximum.
    if let RemoteAuthorityRecordV1::WorkspaceRoleAssignment(assignment) = &mut over_size {
        assignment.principal_id = "x".repeat(MAX_REMOTE_AUTHORITY_PAYLOAD_BYTES + 1);
    }
    assert!(matches!(
        sign_remote_authority_record(&over_size, &signer),
        Err(RemoteError::Authority(_))
    ));
}

fn role_assignment(
    sequence: u64,
    previous_digest: ContentDigest,
    evaluated_head: AuthorityHeadV1,
    key_id: &str,
) -> RemoteAuthorityRecordV1 {
    RemoteAuthorityRecordV1::WorkspaceRoleAssignment(WorkspaceRoleAssignmentV1 {
        api_version: WorkspaceRoleAssignmentApiVersion::default(),
        workspace_id: "019e0000-0000-7000-8000-000000000001".to_owned(),
        assignment_id: format!("019e0000-0000-7000-8000-{sequence:012}"),
        principal_id: "019e0000-0000-7000-8000-000000000004".to_owned(),
        role: WorkspaceRole::ContentReviewer,
        assigned_by_principal_id: "019e0000-0000-7000-8000-000000000007".to_owned(),
        assigned_by_actor_context_digest: cd(0x30),
        assigned_at: ts(),
        evaluated_authority_head: evaluated_head,
        authority_sequence: sequence,
        previous_authority_record_digest: previous_digest,
        authority_key_id: key_id.to_owned(),
    })
}

fn verified(
    record: RemoteAuthorityRecordV1,
    key_id: &str,
    public_key: [u8; 32],
) -> VerifiedRemoteAuthorityRecord {
    VerifiedRemoteAuthorityRecord {
        record_digest: record.digest(),
        record,
        envelope_digest: cd(0xEE),
        signer_key_id: key_id.to_owned(),
        public_key,
    }
}

#[test]
fn chain_accepts_well_formed_prefix() {
    let (_, key_id, public_key) = make_signer(21);
    let resolver = FixedResolver {
        active_key_id: key_id.clone(),
        active_public_key: public_key,
    };
    let initial_head = head(10, cd(0xAB));

    let record1 = role_assignment(11, initial_head.record_digest, initial_head, &key_id);
    let record2 = role_assignment(12, record1.digest(), head(11, record1.digest()), &key_id);
    let record3 = role_assignment(13, record2.digest(), head(12, record2.digest()), &key_id);

    let chain = vec![
        verified(record1.clone(), &key_id, public_key),
        verified(record2.clone(), &key_id, public_key),
        verified(record3.clone(), &key_id, public_key),
    ];
    let new_head = validate_chain(&chain, &resolver, initial_head).unwrap();
    assert_eq!(new_head, head(13, record3.digest()));
}

#[test]
fn chain_rejects_gap_reorder_predecessor_mismatch_key_switch_and_missing_head() {
    let (_, key_id, public_key) = make_signer(22);
    let (_, other_key_id, other_public_key) = make_signer(23);
    let resolver = FixedResolver {
        active_key_id: key_id.clone(),
        active_public_key: public_key,
    };
    let initial_head = head(10, cd(0xAB));

    let record1 = role_assignment(11, initial_head.record_digest, initial_head, &key_id);
    let record2 = role_assignment(12, record1.digest(), head(11, record1.digest()), &key_id);

    // Gap: the second record jumps to sequence 13.
    let gap = vec![
        verified(record1.clone(), &key_id, public_key),
        verified(
            role_assignment(13, record1.digest(), head(11, record1.digest()), &key_id),
            &key_id,
            public_key,
        ),
    ];
    assert!(matches!(
        validate_chain(&gap, &resolver, initial_head),
        Err(RemoteError::Authority(_))
    ));

    // Reorder: sequences regress.
    let reordered = vec![
        verified(record2.clone(), &key_id, public_key),
        verified(record1.clone(), &key_id, public_key),
    ];
    assert!(matches!(
        validate_chain(&reordered, &resolver, initial_head),
        Err(RemoteError::Authority(_))
    ));

    // Predecessor mismatch: second record points at a foreign digest.
    let predecessor_mismatch = vec![
        verified(record1.clone(), &key_id, public_key),
        verified(
            role_assignment(12, cd(0xFF), head(11, record1.digest()), &key_id),
            &key_id,
            public_key,
        ),
    ];
    assert!(matches!(
        validate_chain(&predecessor_mismatch, &resolver, initial_head),
        Err(RemoteError::Authority(_))
    ));

    // Unexpected key switch: the second record is signed by a different key.
    let key_switch = vec![
        verified(record1.clone(), &key_id, public_key),
        verified(record2.clone(), &other_key_id, other_public_key),
    ];
    assert!(matches!(
        validate_chain(&key_switch, &resolver, initial_head),
        Err(RemoteError::Authority(_))
    ));

    // Missing/wrong initial head: the first record does not link to it.
    let wrong_initial_head = head(9, cd(0xEE));
    let chain = vec![verified(record1.clone(), &key_id, public_key)];
    assert!(matches!(
        validate_chain(&chain, &resolver, wrong_initial_head),
        Err(RemoteError::Authority(_))
    ));

    // An empty prefix returns the initial head unchanged.
    assert_eq!(
        validate_chain(&[], &resolver, initial_head).unwrap(),
        initial_head
    );
}
