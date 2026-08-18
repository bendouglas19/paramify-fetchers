# Paramify — what is in the catalog, and what one fetcher declares
# Render from the repo root:  docs/demo/render.sh catalog
#
# Breadth first, then the contract: a fetcher's declaration is the thing you wire
# a manifest against, so the last two frames are `describe` -- one synthetic
# fetcher with targets, and one real cloud fetcher whose credentials are optional
# because it authenticates through a chain that usually hands over no secret.

Output docs/demo/catalog.gif

Set Shell "bash"
Set FontFamily "JetBrainsMono Nerd Font"
Set FontSize 16
Set Width 1320
Set Height 930
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 50ms
Set WindowBar Colorful
Set BorderRadius 10
Set Margin 24
Set MarginFill "#181825"
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
Type "export PS1='$ ' FORCE_COLOR=1; clear"
Enter
Show

# Every category, what it collects, and each fetcher's mode. Long by design --
# what settles on screen is the tail of it.
Sleep 600ms
Type "paramify catalog"
Sleep 400ms
Enter
Sleep 4000ms

Hide
Type "clear"
Enter
Show
Sleep 300ms

# One fetcher's contract: the target fields it fans out over, and the env var
# each one arrives in.
Type "paramify describe demo_audit_logging"
Sleep 400ms
Enter
Sleep 4000ms

Hide
Type "clear"
Enter
Show
Sleep 300ms

# A real one. Its credentials are declared OPTIONAL: supply the key pair, or omit
# it and the credential chain falls through to an instance role, IRSA or SSO --
# none of which hand over a secret at all.
Type "paramify describe aws_iam_roles"
Sleep 400ms
Enter
Sleep 5000ms
