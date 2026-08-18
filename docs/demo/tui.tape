# Paramify TUI — the whole loop without leaving the keyboard
# Render from the repo root:  docs/demo/render.sh tui
#
# Drives the real Textual app by keypress: the welcome screen settles on the one
# manifest a fresh clone ships, then Catalog (with search), Manifest, an actual
# run on the Run tab, the evidence it produced, and the Paramify tab. The run is
# real -- five synthetic fetchers, one deliberately failing target, so the status
# table ends `partial` rather than uniformly green.

Output docs/demo/tui.gif

Set Shell "bash"
Set FontFamily "JetBrainsMono Nerd Font"
Set FontSize 15
Set Width 1280
Set Height 800
Set Padding 14
Set Theme "TokyoNight"
Set TypingSpeed 90ms
Set WindowBar Colorful
Set BorderRadius 10
Set Margin 24
Set MarginFill "#16161E"
Set Framerate 15

# --- hidden setup: venv, the throwaway worktree render.sh built, no real
# --- credentials in the environment (see render.sh), and the demo's one
# --- throwaway token so the run has nothing skipped in it.
Hide
Type "source .venv/bin/activate 2>/dev/null"
Enter
Type "cd ${DEMO_WORKTREE:-/tmp/paramify-demo}"
Enter
Type `for v in $(env | cut -d= -f1 | grep -E '^(AWS|AZURE|OKTA|GITLAB|GOOGLE|DATADOG|KNOWBE4|SENTINELONE|RIPPLING|PARAMIFY)_'); do unset "$v"; done`
Enter
Type "export DEMO_API_TOKEN=demo; clear"
Enter
Show

# Launch -- the welcome screen runs its startup checks, then settles.
Type "paramify tui"
Sleep 500ms
Enter
Sleep 4s

# Open the highlighted manifest -> the workspace, on the Catalog tab.
Enter
Sleep 2200ms

# Search the catalog.
Type "/"
Sleep 600ms
Type "demo"
Sleep 2400ms
Escape
Sleep 900ms

# Manifest tab: the entries, their secrets, and the targets they fan out over.
# Walk down to the one that takes a credential -- 1/2 secrets wired, because the
# second one is optional.
Type "2"
Sleep 2000ms
Down
Down
Down
Down
Sleep 2500ms

# Run tab -- ctrl+r executes the manifest and streams it.
Type "3"
Sleep 1200ms
Ctrl+r
Sleep 7s

# Evidence tab: the run that just finished, and the files it wrote. Open the one
# from the target that failed -- the envelope says what went wrong and where.
Type "4"
Sleep 1800ms
Enter
Sleep 2000ms
Down
Down
Down
Sleep 800ms
Enter
Sleep 3500ms
Escape
Sleep 600ms

# Paramify tab: upload the run, and sync each fetcher's entry script.
Type "5"
Sleep 2500ms

# Back to the Catalog, then quit.
Type "1"
Sleep 1000ms
Type "q"
Sleep 1000ms
