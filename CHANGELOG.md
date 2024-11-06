# @digitalbazaar/vc-bitstring-status-list ChangeLog

## 1.1.0 - 2024-11-dd

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
