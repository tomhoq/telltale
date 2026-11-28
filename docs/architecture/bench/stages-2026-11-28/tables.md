
### per-session (µs per packet)

| | honeypot | debian12 | macos15 | cic-monday |
|---|---|---|---|---|
| packets | 28,772 | 330,048 | 1,113,093 | 4,989,228 |
| capture (read + decode) | 0.9 | 0.4 | 1.1 | 0.4 |
| session assembly | 0.6 | 1.5 | 0.7 | 4.1 |
| dispatch (snapshot + queue) | 0.1 | 0.1 | 0.1 | 0.2 |
| output (store + live lines) | 0.4 | 0.2 | 0.1 | 0.3 |
| end-of-capture summary | 1.1 | 0.2 | 0.0 | 0.2 |
| f0p | 0.5 | 0.2 | 0.1 | 0.4 |
| ja4t | 0.1 | 0.1 | 0.0 | 0.1 |
| ja4h | 0.2 | 0.0 | 0.0 | 0.6 |
| claimed | 0.1 | 0.0 | 0.0 | 0.1 |
| tcpcluster | 3.5 | 0.1 | 0.1 | 0.8 |
| fusion | 0.8 | 0.6 | 0.2 | 0.9 |
| **Telltale itself (sum)** | **3.2** | **2.3** | **2.0** | **5.2** |
| **methods (sum)** | **5.3** | **1.1** | **0.5** | **3.0** |
| **all work (CPU)** | **8.4** | **3.4** | **2.5** | **8.1** |
| wait for workers at the end | 0.1 | 0.0 | 0.0 | 0.0 |
| **wall time** | **3.1** | **2.3** | **2.1** | **5.1** |

workers: 12

### inference-time (µs per packet)

| | honeypot | debian12 | macos15 |
|---|---|---|---|
| packets | 28,772 | 330,048 | 1,113,093 |
| capture (read + decode) | 1.5 | 0.9 | 0.9 |
| session assembly | 1.2 | 2.6 | 1.1 |
| dispatch (snapshot + queue) | 58.2 | 27.9 | 108.4 |
| output (store + live lines) | 5.6 | 11.8 | 7.7 |
| end-of-capture summary | 0.1 | 0.2 | 0.1 |
| f0p | 18.3 | 56.7 | 50.2 |
| ja4t | 15.5 | 0.3 | 17.3 |
| ja4h | 0.2 | 0.0 | 0.1 |
| claimed | 0.0 | 0.0 | 0.0 |
| tcpcluster | 23.8 | 0.4 | 18.5 |
| fusion | 10.3 | 41.6 | 24.6 |
| **Telltale itself (sum)** | **66.6** | **43.4** | **118.2** |
| **methods (sum)** | **68.2** | **99.0** | **110.7** |
| **all work (CPU)** | **134.8** | **142.4** | **228.8** |
| wait for workers at the end | 3.0 | 0.3 | 0.0 |
| **wall time** | **64.3** | **32.3** | **110.8** |

workers: 12
