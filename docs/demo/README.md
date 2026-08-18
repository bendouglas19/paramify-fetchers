# README demos

The GIFs embedded in the top-level `README.md` are generated with
[VHS](https://github.com/charmbracelet/vhs) from the `.tape` scripts here, so
they stay in sync with the CLI instead of being hand-recorded.

| Tape | GIF | Shows |
|---|---|---|
| `firstrun.tape` | `firstrun.gif` | the zero-credential first run — `paramify run manifests/demo.yaml`, then the envelope of the target that deliberately failed |
| `doctor.tape`   | `doctor.gif`   | building a run manifest step by step, then `paramify doctor` naming what is missing and going green after one `export` |
| `catalog.tape`  | `catalog.gif`  | `paramify catalog` and `paramify describe` — every category, then one fetcher's contract, then a real cloud fetcher whose credentials are optional |
| `tui.tape`      | `tui.gif`      | `paramify tui` — welcome, catalog search, manifest, a real run, the evidence it wrote, and the Paramify tab |

Everything on camera comes from the demo program (`manifests/demo.yaml`, the
`demo` category), which needs no credentials and no network. That is what makes
these reproducible: anyone can re-record them, and the run they show is the run
they will get.

## Regenerating

```bash
brew install vhs            # one-time; pulls ffmpeg + ttyd
docs/demo/render.sh         # re-renders all four
docs/demo/render.sh tui     # or just one
```

`render.sh` renders from the repo root and records inside a throwaway **git
worktree** (`/tmp/paramify-demo`, override with `DEMO_WORKTREE`), not in your
checkout. Two reasons:

- A worktree holds only tracked files, so the camera sees what a fresh clone
  sees — one manifest, no prior evidence runs. Recording in a real checkout
  films whatever manifests and run history the recorder happens to have, which
  is how the pre-0.4 `tui.gif` ended up showing its author's personal manifest
  list.
- Those local files routinely name real tenants, subscriptions and programs, and
  this README is public. The worktree keeps them off camera by construction, and
  each tape additionally unsets every `AWS_* / AZURE_* / OKTA_* / …` variable
  before recording.

The worktree path is short and outside `$HOME` on purpose: the runner prints the
absolute run directory, and a home directory in that banner is the one leak a
scrubbed environment does not prevent.

`render.sh` records **HEAD**, so commit before you re-record — it warns if
`fetchers/`, `framework/` or `manifests/` have uncommitted changes, because those
are invisible to the camera.

## Re-record when…

- the TUI's layout or key bindings change (the gif is the only place its design
  is documented visually);
- a command's human output changes shape — `doctor`, `describe`, `catalog`, `run`
  and `evidence` are all on camera;
- the demo program changes: a fetcher added or removed from the `demo` category,
  or `manifests/demo.yaml` edited.

The `.tape` and `.gif` files are committed. Nothing else is: `render.sh` removes
the worktree and the throwaway `docs/demo/.scratch/` on exit.
