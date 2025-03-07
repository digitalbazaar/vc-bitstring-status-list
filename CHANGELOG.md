# @digitalbazaar/vc-bitstring-status-list ChangeLog

## 2.0.1 - 2025-03-07

### Changed
- Update dependencies.
  - `@digitalbazaar/credentials-context@3.2.0`.
  - `@digitalbazaar/vc@7.1.1`.
  - `@digitalbazaar/vc-bitstring-status-list-context@1.1.0`.

## 2.0.0 - 2024-11-06

### Changed
- **BREAKING**: The `verified` property returned from `checkStatus` only
  indicates whether the VC's SLC was property verified, it does not make
  any statement about the `status` value (true/false/other) expressed in
  the SLC for the credential status index. Only `status` indicates the
  value of the status at that index of interest.

## 1.1.0 - 2024-11-06

### Added
- Return `status` value so it can be used instead of `verified` in status
  check information. The `verified` property may be removed in the future,
  instead allowing for business rules to check `status` based against the
  status purpose and not conflating verification of the VC and its related
  SLC with the current status of the VC that was checked.

## 1.0.1 - 2024-11-06

### Fixed
- Ensure credentials that only use the VC v2 context match status type checks.

## 1.0.0 - 2024-08-02

### Changed
- Initial version.
- See git history for changes previous to this release.
