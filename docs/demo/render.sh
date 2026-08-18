#!/usr/bin/env bash
# Regenerate the README demo GIFs from the .tape scripts.
#
#   docs/demo/render.sh            # render all tapes
#   docs/demo/render.sh tui        # render just docs/demo/tui.tape
#
# Requires VHS (brew install vhs — pulls ffmpeg + ttyd). Always renders from the
# repo root so the Output paths line up.
#
# Every tape records inside a throwaway git worktree at $DEMO_WORKTREE, not in
# your checkout. Two reasons, both load-bearing:
#
#   * A worktree holds only TRACKED files, so what the camera sees is what a
#     fresh clone sees — one manifest (manifests/demo.yaml), no prior evidence
#     runs. Recording in a real checkout instead films whatever manifests and run
#     history the recorder happens to have, which is how the old tui.gif ended up
#     showing the recorder's personal manifest list.
#   * Those local manifests and runs routinely name real tenants, subscriptions
#     and programs. The README is public. This keeps them off camera by
#     construction rather than by remembering.
#
# The path is short and outside $HOME on purpose: the runner prints the absolute
# run directory, and a home directory in that banner is the one leak a scrubbed
# environment does not prevent.
set -euo pipefail

cd "$(dirname "$0")/../.."   # repo root

DEMO_WORKTREE=${DEMO_WORKTREE:-/tmp/paramify-demo}

if ! command -v vhs >/dev/null 2>&1; then
  echo "vhs not found. Install with: brew install vhs" >&2
  exit 1
fi

# Record HEAD, so the gifs match a commit rather than a dirty tree. Uncommitted
# work is invisible to the camera — a surprise worth failing loudly over.
if ! git diff --quiet HEAD -- fetchers framework manifests; then
  echo "warning: uncommitted changes under fetchers/, framework/ or manifests/" >&2
  echo "         the recording is of HEAD and will NOT include them." >&2
fi

cleanup() {
  git worktree remove --force "$DEMO_WORKTREE" 2>/dev/null || rm -rf "$DEMO_WORKTREE"
  git worktree prune
  rm -rf docs/demo/.scratch
}
trap cleanup EXIT

rm -rf "$DEMO_WORKTREE"
git worktree prune
git worktree add --detach --quiet "$DEMO_WORKTREE" HEAD
echo "==> recording in $DEMO_WORKTREE (worktree of $(git rev-parse --short HEAD))"

tapes=("$@")
if [ ${#tapes[@]} -eq 0 ]; then
  tapes=(firstrun doctor catalog tui)
fi

for name in "${tapes[@]}"; do
  name=${name%.tape}                 # allow either "tui" or "tui.tape"
  tape="docs/demo/${name}.tape"
  [ -f "$tape" ] || { echo "no such tape: $tape" >&2; exit 1; }
  echo "==> rendering $tape"
  # Each tape starts from a clean slate: no evidence from the previous tape, and
  # the manifest a tape builds is not there for the next one to find.
  rm -rf "$DEMO_WORKTREE/evidence" "$DEMO_WORKTREE/manifest.yaml"
  git -C "$DEMO_WORKTREE" checkout --quiet -- manifests
  vhs "$tape"
done

echo "done."
