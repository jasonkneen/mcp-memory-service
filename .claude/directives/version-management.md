# Version Management - Release Workflow

## Always use the documented release workflow

**Never do manual releases** (major, minor, patch, or hotfixes). Manual workflows miss steps and are error-prone.

## Release Branch Workflow (Adopted 2026-01-27)

```
feature-branches → main (development)
                      ↓
              release/vX.Y.Z (preparation)
                      ↓
                  tag vX.Y.Z
                      ↓
              merge back to main
```

### Workflow Steps:

1. **Development**: All feature/fix branches merge to `main`
2. **Release Preparation**: Create `release/vX.Y.Z` branch from `main`
3. **Version Bump**: Update version files on release branch
4. **PR & Merge**: Create PR, squash-merge it
5. **Tag**: Create annotated tag `vX.Y.Z` on main and push it — the tag push is what
   triggers the publish pipeline (`.forgejo/workflows/release.yml`: PyPI main + lite,
   Docker Hub)
6. **Release notes**: Publish a release object from the tag
7. **Sync**: Release branch deleted, main stays current

### Benefits:
- `main` = active development (current work)
- Release branches only when needed
- No permanent `develop` branch to maintain
- Clear separation of release preparation

## Version Bump Procedure

Always bumped together, in one commit:

1. `src/mcp_memory_service/_version.py` (`__version__ = "X.Y.Z"`) — this is the canonical source
2. `pyproject.toml` (line ~7: `version = "X.Y.Z"`)
3. `README.md` (Latest Release section)
4. `CLAUDE.md` (Current Version line)
5. `CHANGELOG.md` (convert [Unreleased] to [X.Y.Z] with date)
6. `uv lock` to update the dependency lock file

Conditional, and each one is enforced by a CI gate:

- `site/index.html` version strings — required whenever MAJOR.MINOR changes, exempt for
  PATCH (`version-drift-check`, `scripts/ci/check_versions.sh`)
- `claude-hooks/.claude-plugin/plugin.json` — required when anything under
  `claude-hooks/` changed since the last commit that moved the manifest version
  (`plugin-version-check`, `scripts/ci/check_plugin_version.sh`)

Do **not** hand-bump `pyproject-lite.toml`: the publish workflow force-syncs it from
`_version.py`, and a manual value there is what left the lite distribution stuck on an
old version once.

## Release Commands

```bash
# Last release, and what has accumulated since
git tag --list 'v*' --sort=-version:refname | head -1
git log <last-tag>..HEAD --oneline
```

`git describe --tags --abbrev=0` is the wrong tool here — it picks up the non-version
tag `archive/github-workflows-pre-codeberg`.

PR creation, review-comment retrieval, squash-merge, and the release object all run
against the forge REST API (`https://codeberg.org/api/v1`, token from `.env`). The
release automation carries the concrete calls; there is no `gh`-based path for the
release itself.

## Merge Discipline

`main` carries no branch-protection rule, so nothing technically blocks a direct push —
the discipline is convention, not enforcement:

- Never commit straight to `main`; branch first.
- Merge through a PR, squash.
- Verify CI is green on the PR before merging.
- If several sessions share one checkout, isolate into a worktree first.

## Hotfix Workflow (Critical Bugs)

- **Speed target**: 8-10 minutes from bug report to release
- **Process**: Fix, test, version bump, commit, then the documented release workflow
- **Branch**: Can go directly to release branch if urgent
- **Issue management**: Post detailed root cause analysis

## Why Not By Hand

What manual releases have actually cost:

- Forgotten `README.md` update
- Incomplete release notes
- Publish pipeline never verified after the tag push
- Version mismatch between files
- **Real incident (v10.8.0, Feb 8, 2026)**: `_version.py` not updated, so the dashboard
  reported the wrong version

The workflow keeps every version file, the CHANGELOG, and the release notes in step,
which is exactly what goes wrong when the bump is done by hand. That holds for "simple"
hotfixes too.
