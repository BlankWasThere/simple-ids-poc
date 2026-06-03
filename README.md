# Simple IDS
This is a simple singature based Intrusion Detection System (IDS) proof-of-concept.

## Requirements
- [Rust compiler](https://rust-lang.org/)
- [Npcap SDK and runtime](https://npcap.com/)

## Compilation
1. Configure and install **Rust compiler** and **Npcap runtime**.
2. Download the **Npcap SDK** and place the _lib_ files inside the `lib/` or `lib/x64/` directory in the root directory of the project.
3. Run `cargo build --release` to build the binary.

## Working
The tool consistently analyze network traffic and checks for signatures defined in the _signature.sig_ file (one signature per line). The predefined signatures consist of the default SSL CA name of [Quasar RAT](https://github.com/quasar/Quasar).
Quasar uses TLSv1.2 which sends the SSL/TLS certificate unencrypted. We could intercept it and generate an alert if the CA name matches inside a payload.

## Disclaimer
This is a simple IDS POC that should not be used in real world systems as there are just too many variables in them.
