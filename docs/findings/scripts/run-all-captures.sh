set -u
O=/d/Documents/telltale-stats/eval-all
X=/d/Documents/telltale/target/release/examples/os_stats.exe
M=/d/Documents/telltale/methods/manifests
PY=/d/Documents/new-method/.venv/Scripts/python.exe
run() {  # name file
  local name="$1" src="$2" in="$2"
  echo "$(date +%T) start $name"
  if [ "$(head -c 4 "$src" | od -An -tx1 | tr -d ' ')" = "0a0d0d0a" ]; then
    in="$O/$name.tmp.pcap"
    "$PY" -I "$O/ng2pcap.py" "$(cygpath -w "$src")" "$(cygpath -w "$in")" || { echo "  convert failed"; return; }
  fi
  "$X" "$M" "$in" > "$O/$name.tsv" 2> "$O/$name.err"
  echo "$(date +%T) done $name: $(tail -1 "$O/$name.err")"
  if [ "$in" != "$src" ]; then rm -f "${O:?}/${name:?}.tmp.pcap"; fi
}
T=/d/Documents/new-method/data/test
for h in debian12 fedora44 ubuntu2604 macos15 macos26; do run "lab-$h" "$T/lab/raw/$h-a/capture.pcap"; done
for h in server2019 server2022 server2025; do run "lab-$h" "$T/lab/raw/$h-a/capture.pcapng"; done
run cic-monday "$T/cic-ids2017/pcap/monday_labeled_tcp.pcap"
run iot23-echo "$T/iot23/pcap/echo-2018-09-21.pcap"
for f in "$T"/unsw-daily/pcap/*.pcap; do run "unsw-daily-$(basename "$f" .pcap)" "$f"; done
for f in "$T"/unsw-iotraffic/pcap/*.pcap; do run "unsw-iot-$(basename "$f" .pcap)" "$f"; done
run honeypot "$T/honeypot/pcap/http-hp-20260928-23.pcap"
run cic-friday "$T/cic-ids2017/pcap/Friday-WorkingHours.pcap"
run mawi2017-5M /d/Documents/telltale-stats/mawi2017_5M.pcap
run mawi2026-5M /d/Documents/telltale-stats/mawi2026_5M.pcap
echo ALL-DONE
