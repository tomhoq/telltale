set -u
O=/d/Documents/telltale-stats/timing
E=/d/Documents/telltale/target/release/telltale-pf.exe
T=/d/Documents/new-method/data/test
cd /d/Documents/telltale
for cap in "honeypot:$T/honeypot/pcap/http-hp-20260928-23.pcap" \
           "debian12:$T/lab/raw/debian12-a/capture.pcap" \
           "macos15:$T/lab/raw/macos15-a/capture.pcap" \
           "cic-monday:$T/cic-ids2017/pcap/monday_labeled_tcp.pcap" \
           "mawi2026-5M:/d/Documents/telltale-stats/mawi2026_5M.pcap"; do
  name=${cap%%:*}; file=${cap#*:}
  for mode in per-session inference-time; do
    echo "$(date +%T) $name $mode"
    "$E" --timings --output "$mode" replay -p "$file" 2>/dev/null | sed -n '/=== timings/,$p' > "$O/$name.$mode.txt"
  done
done
echo ALL-DONE
