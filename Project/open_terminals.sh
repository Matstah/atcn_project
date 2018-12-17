#!/bin/bash
PROJECT_PATH=`dirname "$0"` # gives relative path from working dir to where this script is
# PROJECT_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

CD="cd $PROJECT_PATH"
PY='sudo python'

MININET="$CD;sudo p4run;bash"
COPEN="$CD/controller;bash"
TOPEN="$CD/testing;bash"

CEXE="$CD/controller;$PY"
FIREWALL="$CEXE firewall_controller.py;bash"
HEAVY="$CEXE heavy_hitter_controller.py;bash"
SNIFF="$CEXE sniff_controller.py;bash"

echo 'Open mininet'
xterm -e "$MININET" &

echo 'Wait until mininet has started for the y option!!!'
read -p 'Start all controllers (y) or just open additional terminals (n) [can be done immediately]?' choice

case "$choice" in
  y|Y ) xterm -e "$FIREWALL" & xterm -e "$HEAVY" & xterm -e "$SNIFF" & xterm -e "$TOPEN" & xterm -e "$TOPEN" &;;
  n|N ) xterm -e "$COPEN" & xterm -e "$COPEN" & xterm -e "$COPEN" & xterm -e "$TOPEN" & xterm -e "$TOPEN" &;;
  * ) echo 'invalid choice!';;
esac

echo 'Prepared everything!'
exit 0
