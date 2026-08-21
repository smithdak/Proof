#![forbid(unsafe_code)]

use std::{
    fmt, fs,
    io::{self, Read as _},
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use proof_application::{
    ArtifactKind, BindingId, ExitCode, PresentationId, Timestamp,
    authority::{
        AuthenticatedCommandApiVersion, AuthenticatedCommandEnvelopeJson,
        AuthenticatedCommandSigner, AuthenticatedCommandV1, AuthenticatedInvocationApiVersion,
        AuthenticatedInvocationV1, AuthorityAudience, AuthorityError, CommandInputV1,
        MAX_AUTHENTICATED_INVOCATION_BYTES, MAX_COMMAND_LIFETIME_SECONDS,
        SignAuthenticatedCommandV1,
    },
};
use proof_attestation::{
    Ed25519SigningProvider, ProofSigningProvider as _,
    authority::{AuthorityPayloadProfile, sign_authority_payload},
};
use proof_canonical::{canonicalize, digest, parse_strict};
use serde::Deserialize;
use uuid::Uuid;
use zeroize::Zeroize as _;

const CREDENTIAL_API_VERSION: &str = "proof.dev/local-agent-credential/v1";
const MAX_CREDENTIAL_BYTES: usize = 4_096;
#[cfg(unix)]
const CREDENTIAL_DIRECTORY: &str = "/run/proof-agent/credentials";
#[cfg(windows)]
const CREDENTIAL_DIRECTORY: &str = r"C:\ProgramData\Proof\AgentCredentials";
#[cfg(not(any(unix, windows)))]
compile_error!("proof-agent-signer requires a Unix or Windows credential boundary");

#[derive(Debug, Parser)]
#[command(
    name = "proof-agent-signer",
    version,
    about = "Workspace-blind signer for one bounded Proof Agent invocation",
    long_about = None
)]
struct Cli {
    /// Read one semantic `CommandInputV1` from bounded stdin; only `-` is accepted.
    #[arg(long, value_parser = stdin_only)]
    command: String,

    /// Select a separator-free handle in the fixed credential directory.
    #[arg(long)]
    credential: String,
}

fn main() {
    let cli = Cli::parse();
    let exit_code = match run(&cli, io::stdin().lock(), io::stdout().lock()) {
        Ok(()) => ExitCode::Success,
        Err(error) => {
            eprintln!("proof-agent-signer: {}: {}", error.code, error.detail);
            ExitCode::for_problem_code(error.code)
        }
    };
    process::exit(i32::from(exit_code as u8));
}

fn run(cli: &Cli, reader: impl io::Read, mut writer: impl io::Write) -> Result<(), SignerError> {
    if cli.command != "-" {
        return Err(SignerError::malformed(
            "the command source must be exactly `-`",
        ));
    }
    validate_credential_handle(&cli.credential)?;
    let bytes = read_bounded(reader, MAX_AUTHENTICATED_INVOCATION_BYTES)?;
    let command_input = normalized_command_input(&bytes)?;
    let signer = FileCredentialSigner::load(&cli.credential)?;
    let issued_at = current_timestamp()?;
    let expires_at = command_expiry(issued_at)?;
    let invocation = signer
        .sign_authenticated_command(SignAuthenticatedCommandV1 {
            command_input,
            binding_id: signer.binding_id,
            presentation_id: generated_presentation_id(),
            issued_at,
            expires_at,
        })
        .map_err(SignerError::from_authority)?;
    let frame = canonical_invocation(&invocation)?;
    writer
        .write_all(frame.as_bytes())
        .map_err(|_| SignerError::unavailable("stdout is unavailable"))?;
    Ok(())
}

fn stdin_only(value: &str) -> Result<String, String> {
    if value == "-" {
        Ok(value.to_owned())
    } else {
        Err("only `-` is accepted; the Agent signer reads bounded stdin only".to_owned())
    }
}

fn read_bounded(reader: impl io::Read, maximum: usize) -> Result<Vec<u8>, SignerError> {
    let maximum_u64 = u64::try_from(maximum).expect("authenticated input bound fits u64");
    let mut bytes = Vec::new();
    reader
        .take(maximum_u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SignerError::malformed("the command frame is unreadable"))?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(SignerError::malformed(
            "the command frame is empty or exceeds its bound",
        ));
    }
    Ok(bytes)
}

fn normalized_command_input(bytes: &[u8]) -> Result<CommandInputV1, SignerError> {
    let value = parse_strict(bytes)
        .map_err(|_| SignerError::malformed("the command frame is not strict JSON"))?;
    let mut command_input: CommandInputV1 = serde_json::from_value(value)
        .map_err(|_| SignerError::malformed("the command frame does not match CommandInputV1"))?;
    command_input
        .normalize_for_authenticated_execution()
        .map_err(|_| SignerError::malformed("the semantic command input is invalid"))?;
    Ok(command_input)
}

fn canonical_invocation(invocation: &AuthenticatedInvocationV1) -> Result<String, SignerError> {
    let value = serde_json::to_value(invocation)
        .map_err(|_| SignerError::malformed("the invocation cannot be serialized"))?;
    let canonical = canonicalize(&value)
        .map_err(|_| SignerError::malformed("the invocation cannot be canonicalized"))?;
    if canonical.as_bytes().len() > MAX_AUTHENTICATED_INVOCATION_BYTES {
        Err(SignerError::malformed(
            "the signed invocation exceeds its bound",
        ))
    } else {
        Ok(canonical.as_str().to_owned())
    }
}

fn validate_normalized_input(command: &CommandInputV1) -> Result<(), AuthorityError> {
    command
        .validate_for_authenticated_execution()
        .map(|_| ())
        .map_err(|_| AuthorityError::AuthMalformed)
}

fn current_timestamp() -> Result<Timestamp, SignerError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SignerError::signing("the signer clock precedes the Unix epoch"))?;
    let nanoseconds = i128::try_from(duration.as_nanos())
        .map_err(|_| SignerError::signing("the signer clock exceeds the timestamp range"))?;
    Timestamp::from_unix_timestamp_nanos(nanoseconds)
        .map_err(|_| SignerError::signing("the signer clock exceeds the timestamp range"))
}

fn command_expiry(issued_at: Timestamp) -> Result<Timestamp, SignerError> {
    let lifetime = i128::from(MAX_COMMAND_LIFETIME_SECONDS) * 1_000_000_000;
    let expires_at = issued_at
        .unix_timestamp_nanos()
        .checked_add(lifetime)
        .ok_or_else(|| SignerError::signing("the signer clock exceeds the timestamp range"))?;
    Timestamp::from_unix_timestamp_nanos(expires_at)
        .map_err(|_| SignerError::signing("the signer clock exceeds the timestamp range"))
}

fn generated_presentation_id() -> PresentationId {
    PresentationId::from_uuid(Uuid::now_v7())
        .expect("UUIDv7 generation must produce a Presentation identifier")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileCredentialV1 {
    api_version: String,
    binding_id: String,
    key_id: String,
    secret_key_hex: String,
}

struct FileCredentialSigner {
    binding_id: BindingId,
    provider: Ed25519SigningProvider,
}

impl FileCredentialSigner {
    fn load(handle: &str) -> Result<Self, SignerError> {
        let directory = credential_directory();
        Self::load_from_directory(&directory, handle)
    }

    fn load_from_directory(directory: &Path, handle: &str) -> Result<Self, SignerError> {
        validate_credential_handle(handle)?;
        validate_credential_directory(directory)?;
        let path = directory.join(format!("{handle}.json"));
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| SignerError::signing("the credential is unavailable"))?;
        validate_credential_metadata(&metadata)?;
        let file = fs::File::open(&path)
            .map_err(|_| SignerError::signing("the credential is unavailable"))?;
        let mut bytes = Vec::new();
        file.take(u64::try_from(MAX_CREDENTIAL_BYTES).expect("credential bound fits u64") + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| SignerError::signing("the credential is unavailable"))?;
        if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL_BYTES {
            bytes.zeroize();
            return Err(SignerError::signing("the credential has an invalid size"));
        }
        let parsed = serde_json::from_slice::<FileCredentialV1>(&bytes);
        bytes.zeroize();
        let mut credential =
            parsed.map_err(|_| SignerError::signing("the credential is malformed"))?;
        if credential.api_version != CREDENTIAL_API_VERSION {
            credential.secret_key_hex.zeroize();
            return Err(SignerError::signing(
                "the credential version is unsupported",
            ));
        }
        let binding_id = credential.binding_id.parse::<BindingId>().map_err(|_| {
            credential.secret_key_hex.zeroize();
            SignerError::signing("the credential binding is malformed")
        })?;
        let secret = decode_secret_hex(&mut credential.secret_key_hex)?;
        let mut secret = secret;
        let provider = Ed25519SigningProvider::from_secret_bytes(&secret);
        secret.zeroize();
        let metadata = provider
            .metadata()
            .map_err(|_| SignerError::signing("the credential metadata is unavailable"))?;
        if metadata.key_id != credential.key_id {
            return Err(SignerError::signing(
                "the credential key identity does not match its secret",
            ));
        }
        Ok(Self {
            binding_id,
            provider,
        })
    }
}

impl AuthenticatedCommandSigner for FileCredentialSigner {
    fn sign_authenticated_command(
        &self,
        command: SignAuthenticatedCommandV1,
    ) -> Result<AuthenticatedInvocationV1, AuthorityError> {
        command
            .validate()
            .map_err(|_| AuthorityError::AuthMalformed)?;
        if command.binding_id != self.binding_id {
            return Err(AuthorityError::AuthMalformed);
        }
        validate_normalized_input(&command.command_input)?;
        let command_value = serde_json::to_value(&command.command_input)
            .map_err(|_| AuthorityError::AuthMalformed)?;
        let canonical_command =
            canonicalize(&command_value).map_err(|_| AuthorityError::AuthMalformed)?;
        let command_digest = digest(ArtifactKind::CommandV1, &canonical_command);
        let payload = AuthenticatedCommandV1 {
            api_version: AuthenticatedCommandApiVersion::V1,
            audience: AuthorityAudience::for_workspace(command.command_input.workspace_id),
            workspace_id: command.command_input.workspace_id,
            operation: command.command_input.operation,
            binding_id: command.binding_id,
            requesting_principal_id: command.command_input.requesting_principal_id,
            operating_principal_id: command.command_input.operating_principal_id,
            delegation_id: command.command_input.delegation_id,
            command_digest,
            idempotency_key: command.command_input.idempotency_key,
            presentation_id: command.presentation_id,
            issued_at: command.issued_at,
            expires_at: command.expires_at,
        };
        let signed = sign_authority_payload(
            AuthorityPayloadProfile::AuthenticatedCommand,
            &payload,
            &[&self.provider],
        )
        .map_err(|error| AuthorityError::Signing(error.to_string()))?;
        let authentication = AuthenticatedCommandEnvelopeJson::new(signed.envelope_json)
            .map_err(|_| AuthorityError::AuthMalformed)?;
        let invocation = AuthenticatedInvocationV1 {
            api_version: AuthenticatedInvocationApiVersion::V1,
            command_input: command.command_input,
            authentication,
        };
        canonical_invocation(&invocation).map_err(|_| AuthorityError::AuthMalformed)?;
        Ok(invocation)
    }
}

fn validate_credential_handle(handle: &str) -> Result<(), SignerError> {
    let valid = !handle.is_empty()
        && handle.len() <= 64
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(SignerError::malformed("the credential handle is invalid"))
    }
}

fn credential_directory() -> PathBuf {
    PathBuf::from(CREDENTIAL_DIRECTORY)
}

fn validate_credential_directory(directory: &Path) -> Result<(), SignerError> {
    let metadata = fs::symlink_metadata(directory)
        .map_err(|_| SignerError::signing("the credential directory is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SignerError::signing(
            "the credential directory is not a regular directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o7777 != 0o700 {
            return Err(SignerError::signing(
                "the credential directory permissions must be 0700",
            ));
        }
    }
    Ok(())
}

fn validate_credential_metadata(metadata: &fs::Metadata) -> Result<(), SignerError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SignerError::signing("the credential is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o7777 != 0o600 {
            return Err(SignerError::signing(
                "the credential permissions must be 0600",
            ));
        }
    }
    Ok(())
}

fn decode_secret_hex(value: &mut String) -> Result<[u8; 32], SignerError> {
    if value.len() != 64 {
        value.zeroize();
        return Err(SignerError::signing(
            "the credential secret has an invalid size",
        ));
    }
    let bytes = value.as_bytes();
    let mut decoded = [0_u8; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]);
        let low = hex_nibble(pair[1]);
        let (Some(high), Some(low)) = (high, low) else {
            value.zeroize();
            decoded.zeroize();
            return Err(SignerError::signing("the credential secret is malformed"));
        };
        decoded[index] = (high << 4) | low;
    }
    value.zeroize();
    Ok(decoded)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[derive(Debug)]
struct SignerError {
    code: &'static str,
    detail: String,
}

impl SignerError {
    fn malformed(detail: impl Into<String>) -> Self {
        Self {
            code: "proof.auth.malformed",
            detail: detail.into(),
        }
    }

    fn signing(detail: impl Into<String>) -> Self {
        Self {
            code: "proof.auth.signing_failed",
            detail: detail.into(),
        }
    }

    fn unavailable(detail: impl Into<String>) -> Self {
        Self {
            code: "proof.dependency.unavailable",
            detail: detail.into(),
        }
    }

    fn from_authority(error: AuthorityError) -> Self {
        match error {
            AuthorityError::AuthMalformed => Self::malformed("the command frame is malformed"),
            AuthorityError::Signing(detail) => Self::signing(detail),
            _ => Self::signing("the invocation could not be signed"),
        }
    }
}

impl fmt::Display for SignerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for SignerError {}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{Cursor, Write as _},
    };

    use proof_application::authority::AuthenticatedInvocationV1;
    use proof_attestation::{
        Ed25519SigningProvider, ProofSigningProvider as _,
        authority::{AuthorityPayloadProfile, verify_authority_envelope},
    };

    use super::*;

    const STATUS_COMMAND: &str =
        include_str!("../../../conformance/v1/authority/vectors/semantic-command.valid.json");

    #[test]
    fn cli_and_handle_accept_only_bounded_stdin_and_an_opaque_handle() {
        assert!(
            Cli::try_parse_from([
                "proof-agent-signer",
                "--command",
                "-",
                "--credential",
                "agent-a",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "proof-agent-signer",
                "--command",
                "command.json",
                "--credential",
                "agent-a",
            ])
            .is_err()
        );
        for invalid in ["", ".", "../agent", "agent/key", "agent\\key", "agent.json"] {
            assert!(validate_credential_handle(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn credential_signer_emits_one_canonical_verified_frame() {
        let directory = TestDirectory::new();
        write_credential(directory.path(), "agent-a", [42_u8; 32]);
        let signer =
            FileCredentialSigner::load_from_directory(directory.path(), "agent-a").unwrap();
        let command_input = normalized_command_input(STATUS_COMMAND.as_bytes()).unwrap();
        let invocation = signer
            .sign_authenticated_command(SignAuthenticatedCommandV1 {
                command_input,
                binding_id: signer.binding_id,
                presentation_id: "019c0000-0000-7000-8000-000000000006".parse().unwrap(),
                issued_at: "2026-08-17T20:02:00Z".parse().unwrap(),
                expires_at: "2026-08-17T20:07:00Z".parse().unwrap(),
            })
            .unwrap();
        let frame = canonical_invocation(&invocation).unwrap();
        let parsed = parse_strict(frame.as_bytes()).unwrap();
        let reparsed: AuthenticatedInvocationV1 = serde_json::from_value(parsed).unwrap();
        assert_eq!(reparsed, invocation);
        let metadata = signer.provider.metadata().unwrap();
        verify_authority_envelope::<serde_json::Value>(
            invocation.authentication.as_str().as_bytes(),
            AuthorityPayloadProfile::AuthenticatedCommand,
            &[metadata.key_id.as_str()],
        )
        .unwrap();
    }

    #[test]
    fn bounded_reader_rejects_empty_and_excessive_frames() {
        assert!(read_bounded(io::empty(), 16).is_err());
        assert_eq!(
            read_bounded(Cursor::new(vec![b'x'; 16]), 16).unwrap().len(),
            16
        );
        assert!(read_bounded(Cursor::new(vec![b'x'; 17]), 16).is_err());
    }

    #[test]
    fn public_failure_codes_and_exit_codes_are_stable() {
        let malformed = normalized_command_input(b"{").unwrap_err();
        assert_public_error(
            &malformed,
            "proof.auth.malformed",
            "the command frame is not strict JSON",
            ExitCode::Authorization,
        );

        let directory = TestDirectory::new();
        write_credential(directory.path(), "valid", [42_u8; 32]);
        let missing = FileCredentialSigner::load_from_directory(directory.path(), "missing")
            .err()
            .unwrap();
        assert_public_error(
            &missing,
            "proof.auth.signing_failed",
            "the credential is unavailable",
            ExitCode::Authorization,
        );
        let malformed_path = directory.path().join("malformed.json");
        fs::write(&malformed_path, b"{").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&malformed_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let bad_credential =
            FileCredentialSigner::load_from_directory(directory.path(), "malformed")
                .err()
                .unwrap();
        assert_public_error(
            &bad_credential,
            "proof.auth.signing_failed",
            "the credential is malformed",
            ExitCode::Authorization,
        );

        let mut failing_writer = FailingWriter;
        let unavailable = failing_writer
            .write_all(b"one signed frame")
            .map_err(|_| SignerError::unavailable("stdout is unavailable"))
            .unwrap_err();
        assert_public_error(
            &unavailable,
            "proof.dependency.unavailable",
            "stdout is unavailable",
            ExitCode::Unavailable,
        );
    }

    fn assert_public_error(error: &SignerError, code: &str, detail: &str, exit_code: ExitCode) {
        assert_eq!(error.code, code);
        assert_eq!(error.detail, detail);
        assert_eq!(ExitCode::for_problem_code(error.code), exit_code);
        assert_eq!(
            format!("proof-agent-signer: {}: {}", error.code, error.detail),
            format!("proof-agent-signer: {code}: {detail}")
        );
    }

    struct FailingWriter;

    impl io::Write for FailingWriter {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "deterministic test failure",
            ))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn write_credential(directory: &Path, handle: &str, secret: [u8; 32]) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let provider = Ed25519SigningProvider::from_secret_bytes(&secret);
        let key_id = provider.metadata().unwrap().key_id;
        let path = directory.join(format!("{handle}.json"));
        fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "api_version": CREDENTIAL_API_VERSION,
                "binding_id": "019c0000-0000-7000-8000-000000000004",
                "key_id": key_id,
                "secret_key_hex": encode_secret_hex(secret),
            }))
            .unwrap(),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn encode_secret_hex(secret: [u8; 32]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(64);
        for byte in secret {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("proof-agent-signer-{}", Uuid::now_v7()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
