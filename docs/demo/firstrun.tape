# Paramify — the zero-credential first run
# Render from the repo root:  docs/demo/render.sh firstrun
#
# The point of this one: the whole pipeline runs before you have wired up a single
# real service. It collects nine synthetic invocations, one of them deliberately
# fails, and the evidence for the failed one says why.

Output docs/demo/firstrun.gif

Set Shell "bash"
Set FontSize 16
Set Width 1240
Set Height 540
Set Padding 20
Set Theme "TokyoNight"
Set TypingSpeed 50ms
Set Framerate 24

# --- hidden setup: venv, the throwaway worktree render.sh built, a clean prompt,
# --- and an environment with no real credentials in it (see render.sh).
Hide
Type "source .venv/bin/activate 2>/dev/null"
Enter
Type "cd ${DEMO_WORKTREE:-/tmp/paramify-demo}"
Enter
Type `for v in $(env | cut -d= -f1 | grep -E '^(AWS|AZURE|OKTA|GITLAB|GOOGLE|DATADOG|KNOWBE4|SENTINELONE|RIPPLING|PARAMIFY|DEMO)_'); do unset "$v"; done`
Enter
Type "export PS1='$ '; clear"
Enter
Show

# The one credential the demo program takes, and it can be anything at all --
# nothing is sent anywhere.
Sleep 700ms
Type "export DEMO_API_TOKEN=demo"
Sleep 300ms
Enter
Sleep 600ms

# Collect. Five fetchers, nine invocations, no cloud account.
Type "paramify run manifests/demo.yaml"
Sleep 400ms
Enter
Sleep 5s

Hide
Type "clear"
Enter
Show
Sleep 400ms

# One target failed. The envelope says which, and why -- reported by the fetcher,
# not scraped off the end of its stderr.
Type "paramify evidence evidence/run-*/demo_audit_logging_demo-sandbox.json | head -16"
Sleep 400ms
Enter
Sleep 4s
