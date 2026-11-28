import sys, dpkt
src, dst = sys.argv[1], sys.argv[2]
with open(src,'rb') as f, open(dst,'wb') as g:
    r = dpkt.pcapng.Reader(f)
    w = dpkt.pcap.Writer(g, snaplen=65535, linktype=r.datalink())
    for ts, buf in r: w.writepkt(buf, ts)
