set -u
X=/d/Documents/telltale/target/release/examples/os_stats.exe
M=/d/Documents/telltale/methods/manifests
run() { echo "$(date +%T) start $1"; $X $M "$2" > /d/Documents/telltale-stats/fusion/$1.tsv 2> /d/Documents/telltale-stats/fusion/$1.err; echo "$(date +%T) done $1: $(tail -1 /d/Documents/telltale-stats/fusion/$1.err)"; }
run cic /d/Documents/new-method/data/test/cic-ids2017/pcap/monday_labeled_tcp.pcap
run iot23 /d/Documents/new-method/data/test/iot23/pcap/echo-2018-09-21.pcap
run unsw-daily-0923 /d/Documents/new-method/data/test/unsw-daily/pcap/16-09-23.pcap
run unsw-daily-0924 /d/Documents/new-method/data/test/unsw-daily/pcap/16-09-24.pcap
run unsw-iot-echo /d/Documents/new-method/data/test/unsw-iotraffic/pcap/AmazonEcho_44650d56ccd3.pcap
run unsw-iot-withings /d/Documents/new-method/data/test/unsw-iotraffic/pcap/WithingsSleepSensor_0024e42028c6.pcap
run honeypot /d/Documents/new-method/data/test/honeypot/pcap/http-hp-20260928-23.pcap
run mawi2026-5M /d/Documents/telltale-stats/mawi2026_5M.pcap
run mawi2017-5M /d/Documents/telltale-stats/mawi2017_5M.pcap
echo ALL-DONE
