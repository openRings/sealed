sealed

Encrypted environment variables, without breaking your .env workflow.

sealed is a small Rust workspace that gives you:
- a CLI to encrypt values directly in `.env` files (Git-friendly and diffable)
- a tiny library to read and decrypt encrypted values from process environment

What this is
- Encrypt only values, keep keys and file structure intact
- One project key, no prompts, script/CI friendly
- Safe defaults and clear error messages

When it helps
- You want to commit `.env` to git but keep secrets encrypted
- You need a minimal tool that works in shells, pipelines, and CI
- You want a library to read encrypted env vars like `std::env::var`

Quick look
```sh
sealed keygen
sealed set DATABASE_PASSWORD -s -k "<base64-key>" <<<"supersecret"
sealed get DATABASE_PASSWORD -r -k "<base64-key>"
```

What’s inside
- CLI (`cargo-sealed`): `cli/README.md`
  - Commands, examples, exit codes, and env file format
- Library (`sealed-env`): `lib/README.md`
  - API docs and Rust usage examples

Format
Encrypted values are stored as:
```
ENCv1:<base64(nonce)>:<base64(ciphertext)>
```

License
MIT
