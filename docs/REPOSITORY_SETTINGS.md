# Repository Settings

These are the **intended** GitHub settings. **None of them are active yet,**
because this repository has not been published. Tick each one only after
configuring and checking it on GitHub.

## Ruleset for `main`

Under **Settings > Rules > Rulesets**, create a branch ruleset targeting `main`:

- [ ] Require a pull request before merging.
- [ ] Require one approval, once there is a second maintainer who can give it.
      GitHub does not let authors approve their own pull requests.
- [ ] Require these status checks to pass, and require branches to be up to date:
  - `Format and lint`
  - `Test (ubuntu-24.04)`
  - `Test (ubuntu-24.04-arm)`
  - `Test (macos-latest)`
- [ ] Block force pushes.
- [ ] Restrict deletions.
- [ ] Require linear history.
- [ ] Leave the bypass list empty.

The status checks can only be selected after CI has run on GitHub at least once.

## Merging

Under **Settings > General > Pull Requests**:

- [ ] Allow squash merging, using the pull request title as the commit message.
- [ ] Disable merge commits and rebase merging.
- [ ] Automatically delete head branches.

## Security

Under **Settings > Advanced Security**:

- [ ] Enable private vulnerability reporting, then remove the maintainer note from
      [SECURITY.md](../SECURITY.md).
- [ ] Enable Dependabot alerts.
- [ ] Enable secret scanning and push protection.

Under **Settings > Actions > General**:

- [ ] Set the default workflow permissions to read-only.
- [ ] Require approval for workflows from first-time contributors.

## Bootstrapping

An empty repository has nothing for a pull request to target, so a one-time
exception is needed for the first commit:

1. Push a minimal root commit to `main`, containing only the licenses and
   `.gitignore`, before the ruleset exists.
2. Create `chore/bootstrap`, commit the rest in logical commits, and open it as
   the first pull request.
3. Once CI has run and passed on that pull request, create the ruleset.
4. Merge the pull request.
