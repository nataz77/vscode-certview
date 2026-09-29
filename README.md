# CertView

A small VS Code extension that displays certificate details on request from Kubernetes TLS Secret YAML files and from `.crt`, `.cer`, `.pem`, `.pfx` and `.p12` files. For Kubernetes TLS Secret YAML files it reads `tls.crt` from `data` (base64-encoded) or `stringData` (plain PEM) and displays X.509 subject, issuer, validity dates, serial number, SHA-256 fingerprint, subject alternative names, and public-key type. The private key is never displayed. The details panel uses locally bundled Fluent UI Web Components and follows the active VS Code light or dark theme; it does not load UI assets from a CDN.

## Run locally

1. Run `npm install` in this folder.
2. Open this folder in VS Code and press F5 to launch the Extension Development Host.
3. Open a YAML file containing a Kubernetes Secret with `type: kubernetes.io/tls` and `data.tls.crt` or `stringData.tls.crt`.
4. Click the key icon in the editor title toolbar, or run **CertView: Show Certificate Details** from the Command Palette.

## Certificate files and chain validation

- `.crt`, `.cer` and `.pem` files may be PEM (single certificate or bundle) or DER. `.pfx` and `.p12` files are PKCS#12 archives; an empty password is tried first, otherwise a password prompt is shown (the password is used once and never stored).
- The details view shows the full chain from the leaf to the root. Missing issuers are looked up in the operating system trust store (Node.js 22.15+ / 23.10+; older runtimes fall back to the bundled Mozilla roots, and the view says so). Certificates in the file that are not part of the chain are listed separately.
- Validation checks signatures, validity dates, CA constraints and whether the chain ends at a certificate trusted by the system. Revocation (CRL/OCSP), host names and downloading missing intermediates are not handled.

## Details pane

The extension uses a single details pane. While it is open, activating another supported file (YAML, `.crt`, `.pem`, `.pfx`, ...) updates the pane in place instead of opening a new one. Files that are not certificates leave the pane unchanged. Password protected PKCS#12 files show a hint until you run the command on them.

Run `npm test` to compile the extension and execute the parser tests.
