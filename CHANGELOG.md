# Changelog

## Unreleased

- Added the initial implementation: package skeleton, strict schemas, schema
  export, validator parity, YAML compilation, canonical digests, privacy
  utilities, HMAC tokens, and OpenTelemetry-aligned span-plan preview.
- Added fixture manifests, safe fixture path resolution, compiled-suite loading,
  golden drift checks, deterministic fixture runs, and the synthetic prior
  authorization example variants.
- Hardened fixture runs with typed variant configs, explicit case-to-expectation
  links, multi-root fixture validation, source digest checks, and catalog-based
  prior authorization evidence assembly.
- Reworked the prior authorization evidence regression to arise from duplicate
  source/content associations during catalog reconstruction, modeled provider
  selection as layered configuration precedence, added a fake-PHI redaction
  fixture case, and enabled socket-disabled pytest runs.
