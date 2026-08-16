# Renders docs/demo.gif — the pitch, in about 25 seconds.
#
#   npm install -g secretgate
#   vhs demo/demo.tape
#
# Scripted rather than hand-recorded so it regenerates when behaviour changes,
# and so a reviewer can read exactly what is being demonstrated instead of
# taking a GIF on trust.
#
# Render it on Linux or macOS. VHS drives a real terminal through ttyd, and
# ttyd cannot spawn bash on Windows — the tape parses and then hangs forever.
# `.github/workflows/demo.yml` renders it on an Ubuntu runner for that reason.
#
# VHS has no escaping for nested quotes inside Type, so anything needing them
# lives in demo/setup.sh.

# Quoted: VHS's parser splits an unquoted path on the dot.
Output "docs/demo.gif"

Set Shell bash
Set FontSize 16
Set Width 1200
Set Height 700
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms

Hide
Type "bash demo/setup.sh && cd /tmp/secretgate-demo && clear"
Enter
Sleep 2s
Show

Type "# A .env you are about to paste into an AI agent."
Enter
Sleep 1s

Type "cat .env"
Enter
Sleep 3s

Type "clear"
Enter
Sleep 500ms

Type "# What the agent actually receives:"
Enter
Sleep 800ms

Type "secretgate filter < .env"
Enter
Sleep 4s

Type "# Same structure. Same providers. No secrets."
Enter
Sleep 2s

Type "clear"
Enter
Sleep 500ms

Type "# The agent edits the file and hands it back."
Enter
Sleep 1s

Type "secretgate filter < .env > redacted.env"
Enter
Sleep 800ms

Type "sed 's|db.internal|db.prod.internal|' redacted.env | secretgate filter --rehydrate"
Enter
Sleep 4s

Type "# Edit kept. Real values restored. The model never saw one."
Enter
Sleep 3s
