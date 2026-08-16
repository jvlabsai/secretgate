# Renders docs/demo.gif — the pitch, in about 20 seconds.
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
# Deliberately no `clear` between the stages: the before and the after have to
# be on screen together or the viewer has to hold the first half in their head,
# and that is the whole thing being demonstrated. The window is sized to fit the
# full story with no dead space, since this gets embedded in a README.

# Quoted: VHS's parser splits an unquoted path on the dot.
Output "docs/demo.gif"

Set Shell bash
Set FontSize 14
Set Width 1280
Set Height 500
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms

Hide
Type "bash demo/setup.sh && cd /tmp/secretgate-demo && clear"
Enter
Sleep 2s
Show

Type "# A .env you are about to paste into an AI agent:"
Enter
Sleep 800ms

Type "cat .env"
Enter
Sleep 2500ms

Type "# What the agent actually receives:"
Enter
Sleep 800ms

Type "secretgate filter < .env"
Enter
Sleep 3500ms

Type "# The agent edits the file and hands it back:"
Enter
Sleep 800ms

Type "secretgate filter < .env > redacted.env"
Enter
Sleep 500ms

Type "sed 's|db.internal|db.prod.internal|' redacted.env | secretgate filter --rehydrate --quiet"
Enter
Sleep 3500ms

Type "# Edit kept. Secrets restored. The model never saw one."
Enter
Sleep 3s
