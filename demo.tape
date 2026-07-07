Output pristine_demo.mp4
Output pristine_demo.gif

Set Theme "Dracula"
Set FontFamily "JetBrains Mono"
Set FontSize 13
Set Width 1300
Set Height 650
Set WindowBar Colorful

Hide
# 1. Force the terminal size so Python 'rich' tables don't glitch into garbage
Type "export COLUMNS=130"
Enter
Type "export LINES=35"
Enter
# 2. Force standard colors and strip Pywal overrides
Type "export TERM=xterm-256color"
Enter
Type "export COLORTERM=truecolor"
Enter
Type "source venv/bin/activate"
Enter
Type "export PS1='> '"
Enter
Type "clear"
Enter
Show

Sleep 1s
# 3. Scanning a local subnet looks much more "real" and fast than scanme.nmap.org
Type "python3 main.py -t 192.168.1.0/24 -p '80,443,22,8080' -m async"
Sleep 1s
Enter

Sleep 15s
