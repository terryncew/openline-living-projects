# Provenance

## Original candidate

- Internal RC3 source archive: `OPENLINE_RC3_COMPLETE_SOURCE.tar.gz`,
  877,913 bytes, Drive file `1esYaYBKcPVfqpH8Xtm5ebPm__uWMzSph`,
  SHA-256 `803d49151d3ffed87a16534e16d73ef67c26001f88bbfd8b0d2de6a69f0f8801`.
- Internal RC3 HEAD: `a9ef5d120ef53daf4db19fbb2204022ae0410c64`,
  branch `engineering/argon-living-projects-rc3-20261101`.
- Internal manifest `RELEASE-CANDIDATE-RC3-SHA256SUMS.txt`: 129/129
  files verified before patching. Manifest self-hash
  `9523a21184067a3a64dca306c935eb1b82c41e2778d68734c2f2022bc72b66df`.
- Git lineage verified from the archive's own objects: RC3
  `a9ef5d12...` → RC2 `32aca9360e9c44cdfd1e48b3c319f7998c89f075` →
  RC1 `6b7ace606c3065e17765ef561f7a5e1f083207cf`. RC1 is a root
  commit in that archive; the recovery manual's base snapshot
  `f5aa372c...` is not present as an object.
- Embedded hardened watchdog zip in the internal tree hashed to
  `64599f904b972f2febbbcf61da1aa036125a75b1eecbdd427d10f548b320a105`,
  the independently verified hardened prototype hash. That zip file
  itself is excluded from this public package; its source files are
  included.
- Historical Protect-005 manifest hash in the internal tree:
  `89c7ceb2a2a18584ac5390a5aa2f72c8ee72609dce9cc714ed4c3fcaa6d91640`.

## Correction applied

- Manager post-audit handoff: Drive file `1PKm-AOFrgjDpJDQw7AULZfQw2-sb1R5j`,
  `RC3_MANAGER_POST_MUSE_HANDOFF.md`, SHA-256
  `0f3c60309ee8a4ad287c9d392da69e93f5d7624d559bb2ba8ee031d4d3e86933`.
- Combined correction patch: Drive file
  `11YowGTOsN1PmmBlMg4Ruc-5R5GXdyvnz`,
  `RC3_MANAGER_R1_R2_FIX.patch`, SHA-256
  `e691486f41c079d0738d30a6b43e0b34511a754b41203735c45cde108ba61564`.
- The patch was applied once, alone, to a fresh pristine extraction.
  `git apply --check` passed. The resulting diff is exactly 4 files,
  matching the handoff description. The earlier SQLite patch
  (`RC3_SQLITE_CONNECTION_FIX.patch`, SHA-256
  `b72f8e96aa728336c4e4d14d98352599c3474b8ed6b7a7bcbee44659f543b7f5`)
  was NOT stacked: re-applying it to the corrected tree fails, as
  expected, because its change is already included in the combined patch.
- Corrected code file hashes (see also `RELEASE_NOTES.md`):
  - `durable_watchdog.py`: `a7b81fe1f17639956e63955246fcd8073c61a4818fd2abeef2ec1ed49c1487ba`
  - `mcp_server.py`: `c8beb19b25157e827e216737f58bb1de0e2951fe2e9bcc8db0684563981a4b7c`
  - `openline` (script): content `0161383e66e3987606269638fd755632f07dda9524242792821a378a7df79f66`, mode 100755

## Packaging edits (public package only, not code changes)

The following edits were made when curating the public package from
the corrected tree. No product code logic was changed by these edits,
except the two corrections above, which are already in the corrected
tree.

1. Excluded files and directories (see below).
2. Removed `__pycache__` build artifacts and the internal manifests
   (`RELEASE-CANDIDATE-RC3-SHA256SUMS.txt`, `SHA256SUMS.txt`), which
   no longer match the curated file set. They are replaced by
   `PUBLIC-SHA256SUMS.txt`, generated from the curated files in this
   package. Verify with `sha256sum -c PUBLIC-SHA256SUMS.txt`.
3. Edited `experiments/OPENLINE-RELEASE-001/README.md` license and
   evaluation sections: the private-evaluation notice is superseded
   by the Apache-2.0 public license in this package, and references
   to deleted internal evaluation files were removed.
4. Removed experiment `README.md` files other than the release README,
   and the MCP-entry adoption note, because they carried internal
   private/hold status headers. Their code and tests are included;
   their internal status documents are not.
5. Adapted the top-level `QUICKSTART.md` for a git clone (instead of
   a tarball) and for `PUBLIC-SHA256SUMS.txt`, and updated its
   classification and verification paragraph to the public package.
6. Normalized file permissions: regular files 644, the `openline`
   script 755. (The verifier's workspace umask otherwise produces
   660/770 modes, which are not suitable for a public archive.)
7. Added top-level public documentation: `README.md`, `QUICKSTART.md`
   (adapted), `SECURITY.md`, `RELEASE_NOTES.md`, this file,
   `LICENSE` (Apache-2.0), and `NOTICE`.

## Excluded from the public package

- `docs/` — the internal finish-line roadmap, marked
  PRIVATE / DRAFT / NO RELEASE in its own header.
- All internal handoff, verdict, breakthrough, gate, closeout, and
  independent-review documents (`HANDOFF.md`, `BREAKTHROUGH.md`,
  `VERDICT.md`, `GATE_A_PROTOCOL.md`, `RELEASE_EVIDENCE.md`,
  `ARGON_OUTSIDER_TRIAL.md`, `LOCAL_CLOSEOUT.md`, `MUSE_CLOSEOUT.md`,
  `INDEPENDENT-REVIEW.md`, `PROMOTION_ADMISSION_CORRECTION_HANDOFF.md`).
- `experiments/OPENLINE-TOE-GRAPH-EXPLORATION-001/` in full,
  including coherence-dynamics source and recovered text. TOE
  equations are outside release enforcement and are not published here.
- `experiments/OPENLINE-GRAPH-WATCHDOG-001/provenance/` — the
  private watchdog zip bundle. The watchdog source files are included.
- `experiments/OPENLINE-RELEASE-001/evaluation/` — neutral
  evaluation materials. They are not part of the product.
- `experiments/*/evidence/` — internal evidence logs and JSON files.
- `experiments/OPENLINE-MCP-ENTRY-001/EVIDENCE_MANIFEST.json`,
  `experiments/OPENLINE-PROTECT-005/SHA256SUMS.txt` — stale internal
  manifests that reference deleted or absent files.
- Experiment `README.md` files other than the release README, and
  the MCP-entry adoption note, for the reason in packaging edit 4.

## What was NOT verified in this public package

- Live coding-agent host, outsider adoption, production isolation
  beyond a container, macOS/Windows, multi-agent or held-out tasks,
  cost/latency superiority, Python 3.13.
- The original internal archive, the internal gate report, and the
  internal evidence bundle are not in this repository. Their hashes
  above are the link back to the internal verification.

## Public package identity

- Repository: https://github.com/terryncew/openline-living-projects
- Tag: `v0.1.0-rc3-corrected`
- Manifest: `PUBLIC-SHA256SUMS.txt` in this repository. Run
  `sha256sum -c PUBLIC-SHA256SUMS.txt` from the repository root.
  The manifest covers every file in the package except itself.
  Its own SHA-256 is recorded in the post-audit gate report held
  with the founder, so a later change to the manifest is detectable
  against that report.
- The existing public repositories `terryncew/openline` (developer
  preview from the earlier #159 package) and `terryncew/openline-connect`
  are preserved unchanged. This is a separate repository so that
  earlier publication is not overwritten.
