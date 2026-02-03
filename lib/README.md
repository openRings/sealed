sealed-env (Library)

Small helper library that reads encrypted environment variables from the
process environment and decrypts them using `SEALED_KEY`.

Install
Add to `Cargo.toml`:
```toml
sealed-env = "0.1"
```

Behavior
- Reads from process environment.
- Encrypted values must start with `ENCv1:`.
- Uses `SEALED_KEY` from the environment to decrypt.
- Returns UTF-8 plaintext on success.

API
- `sealed_env::var(name)`
  - Strict: requires the variable to be present and encrypted.
- `sealed_env::var_or_plain(name)`
  - Lenient: returns plaintext as-is if the value is not encrypted.
- `sealed_env::var_optional(name)`
  - Optional: returns `Ok(None)` if the variable is not set; otherwise decrypts if needed.

Examples
```rust
use sealed_env::{var, var_optional, var_or_plain};

std::env::set_var("SEALED_KEY", "<base64-key>");
std::env::set_var("DATABASE_PASSWORD", "ENCv1:...:...");

let secret = var("DATABASE_PASSWORD")?;
let plain = var_or_plain("FEATURE_FLAG")?;
let maybe = var_optional("OPTIONAL_SECRET")?;
# Ok::<(), sealed_env::SealedEnvError>(())
```

Errors
- `MissingVar`: requested variable is not set.
- `MissingKey`: `SEALED_KEY` is not set.
- `NotEncrypted`: value is not prefixed with `ENCv1:`.
- `Crypto`: base64 or decryption errors.
