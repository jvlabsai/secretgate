# Renders docs/demo.gif — the 20-second pitch.
#
#   go install github.com/charmbracelet/vhs@latest
#   vhs demo/demo.tape
#
# Scripted rather than hand-recorded so it can be regenerated when the output
# changes, and so a reviewer can see exactly what is being demonstrated instead
# of taking a GIF on trust.

Output docs/demo.gif

Set Shell bash
Set FontSize 17
Set Width 1300
Set Height 760
Set Padding 22
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Set PlaybackSpeed 1.0

Hide
Type "cd $(mktemp -d) && clear" Enter
# The demo secret is assembled at runtime, for the same reason the test
# fixtures are: no file in this repo should hold a live-looking key.
Type "AWSK=$(printf '%s' AKIA 4KTNQ7VZL2WXMP3D)" Enter
Type "GHT=$(printf '%s' ghp _ 9fK2mQ7xLp4RtY8vN3wZ6bH1jC5sD0aG4eU2)" Enter
Type "printf 'AWS_ACCESS_KEY_ID=%s\nDATABASE_URL=postgres://svc:h4Kd9wQz2Lp8Nx7@db.internal:5432/orders\nGITHUB_TOKEN=%s\n' \"$AWSK\" \"$GHT\" > .env" Enter
Type "clear" Enter
Show

Type "# You are about to paste a .env into an AI agent."
Enter
Sleep 1200

Type "cat .env"
Enter
Sleep 2600

Type "clear" Enter
Sleep 300

Type "# This is what the agent would actually receive."
Enter
Sleep 1000

Type "secretgate filter < .env"
Enter
Sleep 3800

Type "clear" Enter
Sleep 300

Type "# Structure intact. Provider intact. Secrets gone."
Enter
Sleep 1000
Type "# The agent edits the file and hands it back:"
Enter
Sleep 1200

Type "secretgate filter < .env > redacted.env"
Enter
Sleep 800
Type "sed 's|db.internal|db.prod.internal|' redacted.env | secretgate filter --rehydrate"
Enter
Sleep 4200

Type "# Real values restored locally. The model never saw one."
Enter
Sleep 2600
