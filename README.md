# Kubernetes TLS Certificate Viewer

A small VS Code extension that displays certificate details from a Kubernetes TLS Secret YAML file when explicitly requested. It reads `tls.crt` from `data` (base64-encoded) or `stringData` (plain PEM) and displays X.509 subject, issuer, validity dates, serial number, SHA-256 fingerprint, subject alternative names, and public-key type. The private key is not read or displayed. The details panel uses locally bundled Fluent UI Web Components and follows the active VS Code light or dark theme; it does not load UI assets from a CDN.

## Run locally

1. Run `npm install` in this folder.
2. Open this folder in VS Code and press F5 to launch the Extension Development Host.
3. Open a YAML file containing a Kubernetes Secret with `type: kubernetes.io/tls` and `data.tls.crt` or `stringData.tls.crt`.
4. Click the key icon in the editor title toolbar, or run **Kubernetes TLS: Show Certificate Details** from the Command Palette.

Run `npm test` to compile the extension and execute the parser tests.
