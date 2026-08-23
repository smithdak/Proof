//! Integration tests for the `proof-remote` OIDC identity module.
//!
//! These tests prove byte-exact reproduction of the frozen P-0008
//! collaboration-server vectors for the subject commitment, issuer
//! configuration, public binding, authentication event, and public actor
//! evidence, plus the blind/base64url-no-pad machinery, opening validation,
//! issuer pin rejections, protected→public redaction, and the structural
//! absence of raw issuer/subject material from public evidence.

use proof_canonical::{canonicalize, parse_strict};
use proof_remote::{RemoteOperationV1, derive_key_digest, identity::*};
use serde_json::Value;

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn vector(name: &str) -> Value {
    let path = repo_root()
        .join("conformance/v1/collaboration-server/vectors")
        .join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    parse_strict(&bytes).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn raw_digest(context: &str, value: &Value) -> String {
    let canonical = canonicalize(value).expect("checked-in vector must canonicalize");
    derive_key_digest(context, canonical.as_bytes()).to_string()
}

fn alice_subject() -> OidcAuthenticatedSubjectV1 {
    OidcAuthenticatedSubjectV1 {
        api_version: OidcAuthenticatedSubjectApiVersion::V1,
        issuer: "https://identity.example.test".to_owned(),
        provider: "proof/oidc".to_owned(),
        subject: "human-alice".to_owned(),
    }
}

fn commitment_input(
    blind: [u8; 32],
    subject: OidcAuthenticatedSubjectV1,
    workspace_id: &str,
) -> OidcSubjectCommitmentInputV1 {
    OidcSubjectCommitmentInputV1 {
        api_version: OidcSubjectCommitmentInputApiVersion::V1,
        blind: encode_blind(&blind),
        subject,
        workspace_id: workspace_id.to_owned(),
    }
}

const WORKSPACE_ID: &str = "019e0000-0000-7000-8000-000000000001";

/// The retained commitment vector uses an alternating `I`/`i` blind encoding the
/// 32 bytes `0x22`. Reproduce it exactly rather than relying on an
/// indistinguishable uppercase-only literal.
fn fixed_blind_text() -> String {
    (0..43)
        .map(|index| if index % 2 == 0 { 'I' } else { 'i' })
        .collect()
}

/// Recursively rejects any raw OIDC issuer/subject, opening, token, or blind
/// material from a public evidence value. The only permitted bare `subject` key
/// is the operating Agent's public `ed25519:<hex>` subject, and the only
/// permitted provider is `proof/local-ed25519`.
fn assert_public_safety(value: &Value) {
    match value {
        Value::Object(map) => {
            for key in map.keys() {
                match key.as_str() {
                    "requesting_subject"
                    | "normalized_input_digest"
                    | "opening"
                    | "token"
                    | "blind"
                    | "issuer" => {
                        panic!("public evidence must not carry forbidden `{key}`")
                    }
                    _ => {}
                }
            }
            // A bare `subject` value must be the operating Agent's public
            // `ed25519:<hex>` subject, never a raw OIDC subject string.
            if let Some(subject) = map.get("subject") {
                assert!(
                    subject
                        .as_str()
                        .is_some_and(|value| value.starts_with("ed25519:")),
                    "a bare `subject` value in public evidence must be the operating Agent ed25519 subject"
                );
            }
            // The only permitted provider is the Agent's `proof/local-ed25519`.
            if let Some(provider) = map.get("provider") {
                assert_eq!(
                    provider.as_str(),
                    Some("proof/local-ed25519"),
                    "public evidence may only carry the `proof/local-ed25519` provider"
                );
            }
            for child in map.values() {
                assert_public_safety(child);
            }
        }
        Value::Array(items) => items.iter().for_each(assert_public_safety),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

#[test]
fn frozen_identity_digests_are_byte_exact() {
    // Raw canonical-byte digests, independent of the typed round-trip.
    assert_eq!(
        raw_digest(
            "proof:oidc-authenticated-subject-commitment:v1",
            &vector("oidc-subject-commitment.input.private-test.json"),
        ),
        "blake3:d527780fd72191afe371293b1f2224af4196fb0f7e5ea281831ee2c793e7c3f2"
    );
    assert_eq!(
        raw_digest(
            "proof:oidc-issuer-configuration:v1",
            &vector("oidc-issuer-configuration.valid.json"),
        ),
        "blake3:64cab46b9d5925076a726b80206f365d2e913768a90e0954487cb30b010a9cc7"
    );
    assert_eq!(
        raw_digest(
            "proof:remote-authority-record:v1",
            &vector("oidc-principal-binding.valid.json"),
        ),
        "blake3:07c47a343c09eb7a58fc86a1c0ec07d5e54dbf0b23ce5a1eb3aee946dff6ce39"
    );
    assert_eq!(
        raw_digest(
            "proof:remote-authentication-event:v1",
            &vector("remote-authentication-event.valid.json"),
        ),
        "blake3:8d9e13564123e941ec953411f221b77088566e2421a757edf4895b627b83ee94"
    );
    assert_eq!(
        raw_digest(
            "proof:authenticated-actor-context-evidence:v2",
            &vector("authenticated-actor-context-evidence-v2.human.valid.json"),
        ),
        "blake3:9b208791427c5d25c5d56a0f7487d3ed206ff1de80f4d442feb4859c7abe6c7d"
    );
    assert_eq!(
        raw_digest(
            "proof:authenticated-actor-context-evidence:v2",
            &vector("authenticated-actor-context-evidence-v2.human-agent.valid.json"),
        ),
        "blake3:fe5c016385786accac59e5ada05b865fdeb0cc878ae3a1f131f3426a438b2a8e"
    );

    // Typed round-trips reproduce the same frozen digests.
    let input: OidcSubjectCommitmentInputV1 =
        serde_json::from_value(vector("oidc-subject-commitment.input.private-test.json")).unwrap();
    assert_eq!(
        subject_commitment_digest(&input).unwrap().to_string(),
        "blake3:d527780fd72191afe371293b1f2224af4196fb0f7e5ea281831ee2c793e7c3f2"
    );
    let opening: OidcSubjectCommitmentOpeningV1 =
        serde_json::from_value(vector("oidc-subject-commitment-opening.private-test.json"))
            .unwrap();
    assert!(opening.validate().is_ok());

    let issuer: OidcIssuerConfigurationV1 =
        serde_json::from_value(vector("oidc-issuer-configuration.valid.json")).unwrap();
    assert_eq!(
        issuer.digest().unwrap().to_string(),
        "blake3:64cab46b9d5925076a726b80206f365d2e913768a90e0954487cb30b010a9cc7"
    );
    assert!(issuer.validate().is_ok());

    let binding: OidcPrincipalBindingV1 =
        serde_json::from_value(vector("oidc-principal-binding.valid.json")).unwrap();
    assert_eq!(
        binding.binding_record_digest().unwrap().to_string(),
        "blake3:07c47a343c09eb7a58fc86a1c0ec07d5e54dbf0b23ce5a1eb3aee946dff6ce39"
    );

    let event: RemoteAuthenticationEventV1 =
        serde_json::from_value(vector("remote-authentication-event.valid.json")).unwrap();
    assert_eq!(
        event.digest().unwrap().to_string(),
        "blake3:8d9e13564123e941ec953411f221b77088566e2421a757edf4895b627b83ee94"
    );
    assert!(event.validate().is_ok());
}

#[test]
fn commitment_is_deterministic_and_blinds_are_distinct() {
    let blind = decode_blind(&fixed_blind_text()).unwrap();
    let input = commitment_input(blind, alice_subject(), WORKSPACE_ID);
    assert_eq!(
        subject_commitment_digest(&input).unwrap(),
        subject_commitment_digest(&input).unwrap()
    );
    assert_eq!(
        subject_commitment_digest(&input).unwrap().to_string(),
        "blake3:d527780fd72191afe371293b1f2224af4196fb0f7e5ea281831ee2c793e7c3f2"
    );

    let blind_a = generate_subject_commitment_blind().unwrap();
    let blind_b = generate_subject_commitment_blind().unwrap();
    assert_ne!(blind_a, blind_b, "independent blinds must be distinct");

    let digest_a =
        subject_commitment_digest(&commitment_input(blind_a, alice_subject(), WORKSPACE_ID))
            .unwrap();
    let digest_b =
        subject_commitment_digest(&commitment_input(blind_b, alice_subject(), WORKSPACE_ID))
            .unwrap();
    assert_ne!(
        digest_a, digest_b,
        "distinct blinds must produce distinct commitments"
    );
}

#[test]
fn opening_accepts_exact_preimage_and_rejects_tamper() {
    let blind = decode_blind(&fixed_blind_text()).unwrap();
    let input = commitment_input(blind, alice_subject(), WORKSPACE_ID);
    let commitment = subject_commitment_digest(&input).unwrap();

    let opening = OidcSubjectCommitmentOpeningV1 {
        api_version: OidcSubjectCommitmentOpeningApiVersion::V1,
        commitment,
        input: input.clone(),
    };
    assert!(opening.validate().is_ok());

    // A tampered subject no longer recomputes to the claimed commitment.
    let mut tampered = input.clone();
    tampered.subject.subject = "human-bob".to_owned();
    let bad_opening = OidcSubjectCommitmentOpeningV1 {
        api_version: OidcSubjectCommitmentOpeningApiVersion::V1,
        commitment,
        input: tampered,
    };
    assert!(bad_opening.validate().is_err());

    // A wrong claimed commitment is rejected.
    let wrong = OidcSubjectCommitmentOpeningV1 {
        api_version: OidcSubjectCommitmentOpeningApiVersion::V1,
        commitment: "blake3:0000000000000000000000000000000000000000000000000000000000000000"
            .parse()
            .unwrap(),
        input: input.clone(),
    };
    assert!(wrong.validate().is_err());

    // A non-canonical blind is rejected before the commitment is even compared.
    let mut bad_blind = input.clone();
    bad_blind.blind = format!("{}J", "I".repeat(42));
    let bad_blind_opening = OidcSubjectCommitmentOpeningV1 {
        api_version: OidcSubjectCommitmentOpeningApiVersion::V1,
        commitment,
        input: bad_blind,
    };
    assert!(bad_blind_opening.validate().is_err());
}

#[test]
fn base64url_no_pad_round_trips_without_padding() {
    let blind = generate_subject_commitment_blind().unwrap();
    let encoded = encode_blind(&blind);
    assert_eq!(encoded.len(), 43);
    assert!(
        !encoded.contains('='),
        "base64url-no-pad encoding must never contain padding"
    );
    assert!(
        encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
        "base64url-no-pad encoding must use only the base64url alphabet"
    );
    assert_eq!(decode_blind(&encoded).unwrap(), blind);

    let fixed = "I".repeat(43);
    assert_eq!(encode_blind(&decode_blind(&fixed).unwrap()), fixed);

    // Reject padding characters, non-canonical trailing bits, and wrong length.
    assert!(decode_blind(&format!("{}=", "I".repeat(42))).is_err());
    assert!(decode_blind(&format!("{}J", "I".repeat(42))).is_err());
    assert!(decode_blind(&format!("{}_", "I".repeat(42))).is_err());
    assert!(decode_blind("short").is_err());
    assert!(decode_blind(&"A".repeat(44)).is_err());
}

#[test]
fn issuer_configuration_digest_is_stable_and_pins_reject() {
    let issuer: OidcIssuerConfigurationV1 =
        serde_json::from_value(vector("oidc-issuer-configuration.valid.json")).unwrap();
    assert_eq!(
        issuer.digest().unwrap().to_string(),
        "blake3:64cab46b9d5925076a726b80206f365d2e913768a90e0954487cb30b010a9cc7"
    );
    assert!(issuer.validate().is_ok());

    let mut bad = issuer.clone();
    bad.issuer = "http://identity.example.test".to_owned();
    assert!(bad.validate().is_err(), "issuer must be HTTPS");

    let mut bad = issuer.clone();
    bad.client_id.clear();
    assert!(bad.validate().is_err(), "client_id must be nonempty");

    let mut bad = issuer.clone();
    bad.redirect_uri = "https://proof.example.test/elsewhere".to_owned();
    assert!(
        bad.validate().is_err(),
        "redirect_uri must be the exact preregistered callback"
    );

    let mut bad = issuer.clone();
    bad.token_endpoint = "https://identity.example.test/oauth2/token?x=1".to_owned();
    assert!(
        bad.validate().is_err(),
        "endpoints must carry no query or fragment"
    );

    let mut bad = issuer.clone();
    bad.accepted_id_token_algorithms.clear();
    assert!(
        bad.validate().is_err(),
        "algorithm allowlist must be nonempty"
    );

    let mut bad = issuer.clone();
    bad.accepted_id_token_algorithms = vec!["none".to_owned()];
    assert!(
        bad.validate().is_err(),
        "`none` is never an accepted algorithm"
    );

    let mut bad = issuer.clone();
    bad.accepted_id_token_algorithms = vec!["EdDSA".to_owned(), "EdDSA".to_owned()];
    assert!(
        bad.validate().is_err(),
        "algorithm allowlist must not repeat"
    );

    let mut bad = issuer.clone();
    bad.pkce_method = "plain".to_owned();
    assert!(
        bad.validate().is_err(),
        "pkce_method must be pinned to S256"
    );
}

#[test]
fn private_binding_validates_against_public_record() {
    let private: OidcPrincipalBindingPrivateV1 =
        serde_json::from_value(vector("oidc-principal-binding.private-test.json")).unwrap();
    let public: OidcPrincipalBindingV1 =
        serde_json::from_value(vector("oidc-principal-binding.valid.json")).unwrap();

    assert!(private.validate().is_ok());
    assert!(private.validate_against(&public).is_ok());

    // A public record with a substituted commitment fails the cross-record check.
    let mut bad_public = public.clone();
    bad_public.subject_commitment =
        "blake3:0000000000000000000000000000000000000000000000000000000000000000"
            .parse()
            .unwrap();
    assert!(private.validate_against(&bad_public).is_err());

    // A private record whose raw subject no longer matches its opening fails.
    let mut bad_private = private.clone();
    bad_private.subject.subject = "human-bob".to_owned();
    assert!(bad_private.validate().is_err());
}

#[test]
fn authentication_event_rejects_reversed_time_boundary() {
    let mut event: RemoteAuthenticationEventV1 =
        serde_json::from_value(vector("remote-authentication-event.valid.json")).unwrap();
    assert!(event.validate().is_ok());

    event.expires_at = event.authenticated_at;
    assert!(
        event.validate().is_err(),
        "expiry at authentication time is invalid"
    );
}

#[test]
fn context_redacts_to_exact_public_evidence_for_both_profiles() {
    for (context_file, evidence_file, input_file) in [
        (
            "authenticated-actor-context-v2.human.valid.json",
            "authenticated-actor-context-evidence-v2.human.valid.json",
            "changeset-get-input.private-test.json",
        ),
        (
            "authenticated-actor-context-v2.human-agent.valid.json",
            "authenticated-actor-context-evidence-v2.human-agent.valid.json",
            "release-create-input.private-test.json",
        ),
    ] {
        let context_value = vector(context_file);
        let evidence_value = vector(evidence_file);
        let input = vector(input_file);

        let operation: RemoteOperationV1 =
            serde_json::from_value(context_value["operation"].clone()).unwrap();
        let normalized_digest = normalized_operation_input_digest(&input, &operation).unwrap();
        let projection_digest =
            public_operation_input_projection_digest(&input, &operation).unwrap();
        assert_eq!(
            normalized_digest.to_string(),
            context_value["normalized_input_digest"].as_str().unwrap(),
            "{context_file} normalized-input digest"
        );
        assert_eq!(
            projection_digest.to_string(),
            evidence_value["public_input_projection_digest"]
                .as_str()
                .unwrap(),
            "{evidence_file} public projection digest"
        );
        assert_ne!(normalized_digest, projection_digest);

        let context: AuthenticatedActorContextV2 = serde_json::from_value(context_value).unwrap();
        let evidence = context.redact(projection_digest);
        assert_eq!(
            serde_json::to_value(&evidence).unwrap(),
            evidence_value,
            "{context_file} -> {evidence_file}"
        );
        assert!(evidence.validate().is_ok());
    }
}

#[test]
fn public_evidence_structurally_lacks_raw_subject_material() {
    for (context_file, evidence_file, input_file) in [
        (
            "authenticated-actor-context-v2.human.valid.json",
            "authenticated-actor-context-evidence-v2.human.valid.json",
            "changeset-get-input.private-test.json",
        ),
        (
            "authenticated-actor-context-v2.human-agent.valid.json",
            "authenticated-actor-context-evidence-v2.human-agent.valid.json",
            "release-create-input.private-test.json",
        ),
    ] {
        // The retained vector itself must be public-safe.
        let evidence_value = vector(evidence_file);
        assert_public_safety(&evidence_value);

        // The redaction produced by this module must also be public-safe.
        let context_value = vector(context_file);
        let operation: RemoteOperationV1 =
            serde_json::from_value(context_value["operation"].clone()).unwrap();
        let input = vector(input_file);
        let projection_digest =
            public_operation_input_projection_digest(&input, &operation).unwrap();
        let context: AuthenticatedActorContextV2 =
            serde_json::from_value(context_value.clone()).unwrap();
        let evidence = context.redact(projection_digest);
        let evidence_json = serde_json::to_value(&evidence).unwrap();
        assert_public_safety(&evidence_json);

        // The protected context, by contrast, must still carry the raw subject
        // and normalized-input digest so the redaction is meaningfully tested.
        assert!(context_value.get("requesting_subject").is_some());
        assert!(context_value.get("normalized_input_digest").is_some());
    }
}
