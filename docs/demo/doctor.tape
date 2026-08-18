# Paramify — build a manifest, then preflight it
# Render from the repo root:  docs/demo/render.sh doctor
#
# Replaces the old manifest.tape. Same subject -- building a run manifest step by
# step -- but it now runs to the end: `paramify doctor` says exactly what is
# missing, one export fixes it, and doctor goes green. The old tape stopped at
# "still missing", because the fetcher it wired needed an Okta tenant nobody has
# on camera.

Output docs/demo/doctor.gif

Set Shell "bash"
Set FontSize 16
Set Width 1240
Set Height 700
Set Padding 20
Set Theme "TokyoNight"
Set TypingSpeed 32ms
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

# Start an empty manifest.
Sleep 600ms
Type "paramify manifest init --output-dir ./evidence"
Sleep 300ms
Enter
Sleep 1400ms

# Add a fetcher that takes a credential -- the builder says what is still missing.
Type "paramify manifest add demo_access_review"
Sleep 300ms
Enter
Sleep 2000ms

# Point that secret at an env var. The warning goes away.
Type "paramify manifest set-secret demo_access_review api_token DEMO_API_TOKEN"
Sleep 300ms
Enter
Sleep 1500ms

# Add a fanout fetcher and give it two accounts to collect from.
Type "paramify manifest add demo_audit_logging"
Sleep 300ms
Enter
Sleep 1600ms
Type "paramify manifest add-target demo_audit_logging account=demo-prod-1"
Sleep 300ms
Enter
Sleep 1400ms
Type "paramify manifest add-target demo_audit_logging account=demo-sandbox"
Sleep 300ms
Enter
Sleep 1500ms

Hide
Type "clear"
Enter
Show
Sleep 300ms

# Valid manifest, but not yet a runnable environment: doctor checks both and
# exits non-zero, so it drops straight into CI.
Type "paramify doctor manifest.yaml"
Sleep 400ms
Enter
Sleep 3s

# Set the variable it named...
Type "export DEMO_API_TOKEN=demo"
Sleep 300ms
Enter
Sleep 500ms

# ...and it is ready to run.
Type "paramify doctor manifest.yaml"
Sleep 400ms
Enter
Sleep 3s
