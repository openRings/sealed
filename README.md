sealed

Small CLI for storing encrypted environment variables directly in .env files.
Only values are encrypted, so files remain diffable and Git-friendly. One key per project, no
interactive prompts, safe defaults, and Unix-friendly behavior.

Why use it
- Keep secrets out of plaintext .env files while preserving normal dotenv workflows.
- Encrypt only values, leaving keys and non-secret lines untouched.
- Works well in CI and scripts (stdin, files, no prompts).

How it works
- Encrypts with ChaCha20-Poly1305.
- Uses the variable name as AAD.
- Stores values as: ENCv1:<base64(nonce)>:<base64(ciphertext)>

Install
Build from source:
```sh
cargo build --release
./target/release/sealed --help
```

Commands
```sh
sealed set <VAR_NAME>
sealed get <VAR_NAME>
sealed keygen
```

Examples
Generate a key:
```sh
sealed keygen
sealed keygen -o .sealed.key
```

Set a value from stdin:
```sh
echo -n "supersecret" | sealed set DATABASE_PASSWORD -s -k "<base64-key>"
```

Set a value from a file:
```sh
sealed set DATABASE_PASSWORD -f ./secret.txt -k "<base64-key>"
```

Set a value using key from env:
```sh
export SEALED_KEY="<base64-key>"
echo -n "supersecret" | sealed set DATABASE_PASSWORD -s
```

Read a value:
```sh
sealed get DATABASE_PASSWORD
```

Reveal plaintext (requires key):
```sh
sealed get DATABASE_PASSWORD -r -k "<base64-key>"
```

Env file format example
```
DATABASE_PASSWORD=ENCv1:2s8fK0cPpFJ6x2xZ1C9kLw==:mKJrY0GmZCq7cN5h4F2...
```

Notes
- If a value is not encrypted, sealed get prints it as-is.
- Stdin can be used only once; --stdin and --key-stdin cannot be combined.
- For --value, pass --allow-argv explicitly.

Exit codes
- 0: success
- 1: variable not found
- 2: decryption or key error
- 3: invalid arguments
- 4: env file error
