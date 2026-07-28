# Customer fork workflow

How a customer works on this framework **without publishing their work**, while
still receiving upstream features.

The short version: keep a **private mirror** of this repo, track upstream as a
git remote, and merge our release tags into it. A GitHub fork is *not* how code
flows downstream — a remote is. The fork relationship only buys you GitHub's
"Compare & pull request" button.

This depends on upstream being public, which needs no permission grant and no
fork relationship to read. Confirm before relying on it:

```bash
gh repo view paramify/paramify-fetchers --json visibility
# {"visibility":"PUBLIC"}
```

If it ever isn't, the customer needs an explicit read grant instead — an
outside-collaborator invite or a read-scoped deploy key on their sync runner —
which is a different security review with a per-customer revocation story.

## The constraint

`paramify/paramify-fetchers` is public, and that has two consequences a
compliance team needs to know before anyone clicks *Fork*.

**Forks inherit the upstream's visibility, permanently.** A fork of a public
repo is public, and GitHub disables the visibility control on forks — there is
no "make this private later." Only detaching the fork (a GitHub Support
request, which severs the relationship entirely) changes that. The private-fork
feature some teams remember applies to *internal* repos on GitHub Enterprise,
not to a public upstream.

**Fork networks retain commits forever.** Every commit pushed to any repo in a
fork network stays reachable by SHA from every other repo in that network,
including from the public upstream. Deleting the branch, deleting the fork, or
force-pushing over it does not revoke access. One accidental credential commit
is public permanently, and no follow-up push fixes it.

That matters more here than in a typical repo, because fetcher work is not
generic code. It carries tenant and subscription IDs, resource group and
endpoint names, the population scope of each control, and — if narratives live
alongside the code — a written description of the boundary including its
exceptions and limitations. A public fork publishes a map of the customer's
compliance posture.

## Topology

```
        paramify/paramify-fetchers          public — upstream, source of features
                 │
      ┌──────────┴───────────┐
      │  git remote           │  real GitHub fork
      │  (no fork relation)   │  (optional, see below)
      ▼                       ▼
 <customer>/paramify-fetchers   <customer>/paramify-fetchers
   PRIVATE mirror                 PUBLIC fork
   • all real work                • stays empty except for
   • their own `main`               scrubbed, upstream-bound
   • Paramify as outside            PR branches
     collaborator
```

The private mirror is the working repo. The public fork, if it exists at all, is
a one-way outbound valve that holds nothing sensitive.

## 1. Create the private mirror — Paramify side, once

> **This step runs on a Paramify workstation, on a throwaway bare clone that has
> no customer remote configured, and does not belong in any runbook the customer
> holds.** `git push --mirror` force-updates every ref *and deletes remote refs
> absent locally*. In a repo that has both remotes, one transposed invocation —
> `git push --mirror upstream` — simultaneously leaks every private branch to us
> and destroys upstream history. Don't hand anyone a doc containing this command
> next to a doc telling them to add `upstream`.

The duplicate **must be a mirror**, not a fresh repo with the files copied in.
A file copy shares zero commits with upstream, making every future sync an
`--allow-unrelated-histories` merge that conflicts in every file. A mirror
copies the full commit graph, so our commits and theirs are literally the same
objects and merges behave like any ordinary branch merge.

Have the customer create an empty private repo in their org, then:

```bash
git clone --bare https://github.com/paramify/paramify-fetchers.git
cd paramify-fetchers.git
git push --mirror https://github.com/<customer>/paramify-fetchers.git
cd .. && rm -rf paramify-fetchers.git
```

### Verify the mirror

Tags being present only proves tags copied. Diff the actual ref lists:

```bash
git ls-remote https://github.com/paramify/paramify-fetchers.git | sort > /tmp/up
git ls-remote https://github.com/<customer>/paramify-fetchers.git | sort > /tmp/down
diff /tmp/up /tmp/down
```

Expect divergence **only** in `refs/pull/*`, which GitHub generates per-repo and
never pushes.

Then confirm the default branch is set and a fresh clone lands on it with shared
history:

```bash
git clone https://github.com/<customer>/paramify-fetchers.git && cd paramify-fetchers
git branch --show-current     # must print a branch, not empty
git log --oneline -1          # must match upstream's tip
```

This check is not ceremony. If the destination repo's `HEAD` is unset, the clone
arrives with **no branch checked out**, and the first developer to start
committing begins an orphan history — reintroducing the exact
"refusing to merge unrelated histories" failure the mirror exists to prevent,
through a different door. Set the default branch in the customer repo's settings
before anyone clones it.

## 2. Configure the upstream remote — customer side

Their repo, their `main`. Upstream lives only as a remote; there is no local
"pristine" branch shadowing it, because `upstream/main` and the fetched release
tags are already immutable tracking refs by construction — nothing local can
write to them.

```bash
git remote add upstream https://github.com/paramify/paramify-fetchers.git

# 1. hard-block accidental pushes to upstream
git remote set-url --push upstream no_push

# 2. namespace upstream's tags so they can never collide with the customer's
git config remote.upstream.tagOpt --no-tags
git config --add remote.upstream.fetch '+refs/tags/*:refs/tags/paramify/*'
```

Both lines matter.

**Tags are one flat namespace with no per-remote separation.** The moment the
customer cuts their own `v0.4.0-beta` for an internal release and we publish
`v0.4.0-beta` upstream, the names collide. A plain `git fetch upstream --tags`
then prints `! [rejected] v0.4.0-beta (would clobber existing tag)` — **and
exits 0**. The rejection scrolls past in a wall of fetch output, the command
looks successful, and `git merge v0.4.0-beta` merges the customer's own commit
while everyone believes they took our release. Namespacing removes the collision
entirely: ours land at `refs/tags/paramify/*`, theirs stay untouched at
`refs/tags/*`.

**`no_push`** is a backstop against the `--mirror` hazard above, not a
substitute for keeping that command out of their hands.

## 3. Receive upstream features

Each time we cut a release, two commands:

```bash
git fetch upstream
git merge refs/tags/paramify/v0.4.0-beta
# resolve any conflicts, run the test suite, push
```

Always use the fully-qualified ref. It is unambiguous and self-documenting about
whose tag it is. (Note there is no `upstream/v0.4.0-beta` — tags fetch into
`refs/tags/`, never under `refs/remotes/<remote>/`; the `<remote>/<name>` form
exists only for branches.)

**Merge our tags, not `upstream/main`.** Each sync then becomes a discrete,
named, reviewable change tied to a published release rather than a moving
target — which is what change control wants to point at. Releases here are
curated, not cut per merge (see [`releasing.md`](releasing.md)), so tags are the
right granularity.

For the audit trail, diff against the release rather than a local branch:

```bash
git diff refs/tags/paramify/v0.4.0-beta..main
```

That is the exact delta between shipped Paramify code and everything the
customer changed, anchored to a specific published version. An assessor will
eventually want it, and this makes it free.

## 4. Branch layout

| Branch | Contents | Notes |
|---|---|---|
| `main` | The customer's integration branch | Their default branch. Their fetchers, manifests, config, plus merged upstream releases |
| `feat/*` | One per fetcher or change | PR'd into `main` inside the private repo — this is where Paramify reviews |

One long-lived branch, deliberately. The "upstream's code vs. our work"
distinction is already carried by the remote; encoding it a second time in
branch names makes the default branch the one nobody works on, so PRs base
against the wrong branch by default and every GitHub convention fights them.

Sync conflicts stay near zero regardless, because customer work is mostly **new
files** — `fetchers/<tool>_<thing>/`, their manifests. Conflicts appear only
where they've edited shared framework code, which is exactly where a human
*should* be looking.

## 5. Files that will conflict, and how to stop them

**`pyproject.toml` and `CHANGELOG.md`** conflict on every upstream release if the
customer also bumps versions. So don't: leave the version at whatever we
shipped. If a local build identifier is needed, use a SemVer local suffix
(`0.4.0-beta+<customer>.3`) that no upstream release will collide with. Worth
stating explicitly, because [`releasing.md`](releasing.md) walks *us* through
bumping both files — a developer following our own docs inside their mirror will
manufacture the conflict.

**`manifest.yaml` at the repo root is tracked upstream**, even though
`.gitignore` lists it. Git ignore rules do not apply to already-tracked files,
so the entry is inert here and customer edits get staged by default. Pick one:

- *Don't version the manifest* (simplest) — untrack it once, and the existing
  ignore rule takes over:

  ```bash
  git rm --cached manifest.yaml
  git commit -m "chore: untrack root manifest.yaml (local working file)"
  ```

- *Do version the manifest* (usual for change control) — keep it out of the path
  upstream uses. Drop the `/manifests/` line from `.gitignore` and commit real
  manifests as `manifests/<environment>.yaml`. Root `manifest.yaml` stays
  untracked scratch.

Either way, start from [`examples/`](../examples) rather than editing the root
manifest — those are the canonical samples.

**Secrets are already ignored and must stay that way.** `.env` and `.env.*` are
covered by `.gitignore`; nothing else in the repo should ever hold a credential.
The framework resolves `${env:VAR}` at run time from the environment, so a
manifest references secrets by name and never contains one — which is what makes
committing a manifest safe at all. See
[`config_injection_design.md`](config_injection_design.md).

## 6. Contributing back (optional)

Most customer fetchers are tenant-specific and belong only in the private repo.
When something genuinely generic does emerge — a framework fix, a fetcher worth
adding to the shared library — there are two paths.

**Preferred: Paramify carries the patch.** Paramify already has collaborator
access to the private repo. We pull the change and land it upstream through a
Paramify-side branch. The customer then needs no public GitHub presence at all,
which also removes the last objection available to a security team: a public
fork is itself publicly visible in our forks list, and "this company is building
a FedRAMP evidence pipeline" is signal some teams would rather not emit.

**Alternative: the public fork as an outbound valve.** Fork
`paramify/paramify-fetchers` normally, add it as a third remote, and publish
only scrubbed branches built on a published release:

```bash
git remote add fork https://github.com/<customer>/paramify-fetchers.git

git checkout -b feat/azure-nsg-rules refs/tags/paramify/v0.4.0-beta
git cherry-pick <the generic commits only>   # scrub tenant identifiers first
git push fork feat/azure-nsg-rules
# → open the PR against paramify/paramify-fetchers
```

Branching off the upstream **tag** rather than `main` is the safety property: the
branch cannot contain private commits, because it never had them in its history.

> **Never push `main` to `fork`.** That publishes the entire private history
> permanently — see [fork networks](#the-constraint). There is no undo.

## Upstream history is append-only

From the first customer mirror onward, published history on
`paramify/paramify-fetchers` is immutable. No rewrites, no force-pushes to
`main`, no rewritten tags.

A rewrite upstream — scrubbing a secret out of history is the obvious scenario —
leaves every customer mirror permanently diverged, with no clean recovery: their
work sits on top of commits that no longer exist upstream, so the next merge
either conflicts everywhere or silently reintroduces the scrubbed content. Any
such surgery happens *before* the first mirror is taken. If it ever becomes
unavoidable afterward, it is a coordinated migration per mirror, not a push.

## Alternatives considered

| Approach | Why not |
|---|---|
| Public fork only | Every commit is world-readable, including tenant identifiers and boundary narratives |
| Fork, then make it private | Not possible; GitHub disables visibility changes on forks |
| Fork, then ask Support to detach it | Works, but severs the relationship — a private mirror with extra steps and a support ticket |
| Private fork | GitHub Enterprise *internal* repos only; does not apply to a public upstream |
| Local `main` mirroring upstream + `--ff-only`, work on a second branch | Redundant (`upstream/main` is already an unwritable tracking ref) and adds a permanent failure mode: one stray commit on `main` breaks `--ff-only` forever, and the recovery is `reset --hard` |
