use clap::{ArgGroup, Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "sealed",
    version,
    about = "Store encrypted environment variables in .env files"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "Encrypt and store a variable in an env file")]
    Set(SetArgs),
    #[command(about = "Read a variable from an env file")]
    Get(GetArgs),
    #[command(about = "Generate a new random key (base64)")]
    Keygen(KeygenArgs),
}

#[derive(Args)]
#[command(
    long_about = "Encrypt a plaintext value and store it as ENCv1:<nonce>:<ciphertext> in the env file.\nValue input: exactly one of --stdin, --value (with --allow-argv), or --value-file.\nKey input: exactly one of --key, --key-file, --key-stdin, or SEALED_KEY (env var)."
)]
#[command(
    group(
        ArgGroup::new("value_input")
            .required(true)
            .multiple(false)
            .args(["stdin", "value", "value_file"])
    )
)]
pub struct SetArgs {
    #[arg(
        value_name = "VAR_NAME",
        help = "Environment variable name (used as AAD)"
    )]
    pub var_name: String,

    #[arg(long, short = 's', help = "Read plaintext value from stdin")]
    pub stdin: bool,

    #[arg(
        long,
        short = 'v',
        value_name = "STRING",
        help = "Read plaintext value from argv (requires --allow-argv)"
    )]
    pub value: Option<String>,

    #[arg(
        long = "value-file",
        short = 'f',
        value_name = "PATH",
        help = "Read plaintext value from a file"
    )]
    pub value_file: Option<PathBuf>,

    #[arg(
        long = "allow-argv",
        short = 'a',
        help = "Allow --value to read plaintext from argv"
    )]
    pub allow_argv: bool,

    #[arg(
        long,
        short = 'k',
        value_name = "BASE64",
        help = "Read key from base64-encoded argument"
    )]
    pub key: Option<String>,

    #[arg(
        long = "key-file",
        short = 'K',
        value_name = "PATH",
        help = "Read key from a file (base64)"
    )]
    pub key_file: Option<PathBuf>,

    #[arg(long = "key-stdin", short = 'S', help = "Read key from stdin (base64)")]
    pub key_stdin: bool,

    #[arg(
        long = "env-file",
        short = 'e',
        value_name = "PATH",
        default_value = ".env",
        help = "Path to env file"
    )]
    pub env_file: PathBuf,
}

#[derive(Args)]
#[command(
    long_about = "Read a variable from the env file. If the value is encrypted, a key is required to decrypt it (from --key/--key-file/--key-stdin or SEALED_KEY).\nWithout --reveal, plaintext is not printed."
)]
pub struct GetArgs {
    #[arg(
        value_name = "VAR_NAME",
        help = "Environment variable name (used as AAD)"
    )]
    pub var_name: String,

    #[arg(
        long = "env-file",
        short = 'e',
        value_name = "PATH",
        default_value = ".env",
        help = "Path to env file"
    )]
    pub env_file: PathBuf,

    #[arg(long, short = 'r', help = "Print decrypted plaintext to stdout")]
    pub reveal: bool,

    #[arg(
        long,
        short = 'k',
        value_name = "BASE64",
        help = "Read key from base64-encoded argument"
    )]
    pub key: Option<String>,

    #[arg(
        long = "key-file",
        short = 'K',
        value_name = "PATH",
        help = "Read key from a file (base64)"
    )]
    pub key_file: Option<PathBuf>,

    #[arg(long = "key-stdin", short = 'S', help = "Read key from stdin (base64)")]
    pub key_stdin: bool,
}

#[derive(Args)]
pub struct KeygenArgs {
    #[arg(
        long = "out-file",
        short = 'o',
        value_name = "PATH",
        help = "Write base64 key to a file instead of stdout"
    )]
    pub out_file: Option<PathBuf>,
}
