# CallScope

CallScope is a SIPREC packet capture analyzer.

## What it does

Given a SIPREC Recording Session Call-ID and a set of pcap/pcapng files,
CallScope extracts the relevant SIPREC SIP, RTP, and RTCP traffic and generates
an interactive HTML troubleshooting report plus a paste-ready escalation
summary.

CallScope is a **SIPREC-side capture analyzer**: it assumes the supplied pcaps
were captured between the SBC/SRC (Session Recording Client) and the
recorder/SRS (Session Recording Server). Every check is single-sided — it never
needs the original call leg or a second capture. Because the SBC authors the
recording INVITE, the SIPREC metadata, the SDP, and the forked RTP, anything
self-contradictory in that one capture is provably the SBC's own output.

### v2 analysis (single-sided, SIPREC-only)

- **Internal-consistency proof** — compares the SBC's declared metadata streams
  vs. SDP m-lines vs. observed RTP. "Declared 2, recorded 1" is flagged as an
  internal contradiction the far end cannot be blamed for.
- **SIPREC compliance** — RFC 7865/7866 checks (metadata presence/validity,
  Content-Type, media direction to the recorder), each citing the RFC clause.
- **Re-INVITE burst + codec renegotiation**, **SSRC-change tracking**, and
  **RTCP statistics** (loss, jitter, reporting gaps, BYE).
- **SIP timing/reliability** — post-dial delay, retransmissions, missing ACK,
  failure responses (with hints for 488/491/481/408/503), session-timer refresh.
- **Error-origin-by-IP** — attributes each failure response and BYE to the SBC
  or recorder by the source address that emitted it.
- **Ownership classification** — every finding tagged SBC / Genesys / Network /
  Capture / Unprovable for triage and escalation routing.
- **Plain-English narrative** — a numbered "what happened" story of the session.
- **B2BUA fingerprint**, **capture-quality preflight + SHA-256 chain of
  custody**, **correlation-key export** (join to Genesys/OCOM by time + AOR).
- **Batch/aggregate** mode (failure rate + daily time series) and
  **golden-baseline diff** against a known-good call from the same SBC.

### v2.1 SIPREC label/SSRC lifecycle analysis

- **Metadata decode hardening** — reassembles SIP-over-TCP/TLS multipart bodies,
  decodes hex-encoded bodies, and salvages the `rs-metadata` XML if segmentation
  is imperfect, so the participant/stream/label mapping is actually parsed.
- **Label binding** — joins SDP `a=label` ↔ rs-metadata `<stream>` ↔
  `<participant>`, so every SSRC is shown as e.g. "AGENT (8777357837)" rather
  than a bare port.
- **Hold/retrieve classification** — detects `a=inactive` hold and the
  subsequent retrieve as distinct events (RFC 3264 §8.4), separate from generic
  re-INVITEs.
- **Per-label SSRC lifecycle + coverage gaps** — tracks the sequence of SSRCs
  per participant label and flags the case where an SSRC changes on retrieve such
  that a recorder tracking the old SSRC would miss audio, with an estimated gap
  duration. This is a top-level CRITICAL finding plus a per-participant coverage
  bar in the report.
- **SSRC collision detection** — two SSRCs active on one media port at once.
- **Re-INVITE-burst ↔ SSRC correlation** with asymmetry detection (one leg
  changed SSRC, the other didn't) and a per-label SSRC-stability rate.
- **RFC 5761 RTCP-mux guard** — payload types 64–95 on the RTP port are treated
  as RTCP, not media streams.

The new SIPREC-correctness findings use the `SIPREC-00x` codes:

```
SIPREC-001 [CRITICAL] SSRC changed on retrieve — recording gap likely
SIPREC-002 [WARN]     Re-INVITE burst caused SSRC churn (with asymmetry)
SIPREC-003 [ERROR]    Simultaneous SSRCs on the same media port
SIPREC-004 [INFO]     Hold/retrieve cycle detected
SIPREC-005 [WARN]     SIPREC labels not bound to observed SSRCs
SIPREC-006 [INFO]     RTCP-mux packets on the RTP port (not anomalous)
```

### v0.4 Call quality (MOS / E-model)

CallScope estimates **MOS-CQ** per stream and per RTCP reporting interval using a
local, dependency-free implementation of the ITU-T G.107 E-model — no internet,
no external service. It converts the RTCP loss fraction and interarrival jitter
(already extracted) into an R-factor and a MOS score, picks the codec's
impairment factors (Ie/Bpl) and clock rate from the payload type, and adds a
de-jitter-buffer delay term from the measured jitter on top of a configurable
network-delay baseline (`config.DEFAULT_ONE_WAY_DELAY_MS`, default 30 ms).

The report shows a per-stream MOS summary (avg/min, colour-banded) and a MOS
**trend chart** over the life of the call, with the 3.6 (degraded) and 2.6
(poor) thresholds marked — so a quality cliff that lines up with a hold/retrieve
or a re-INVITE burst is visible at a glance. Findings:

```
MOS_LOW [WARN]   Stream MOS dropped below 3.6 (degraded)
MOS_BAD [ERROR]  Stream MOS dropped below 2.6 (poor)
```

Because RTCP round-trip can't be reliably recovered from a single SIPREC leg,
the network one-way delay is an explicit, documented assumption rather than a
measurement; loss and jitter are real, measured inputs. For wideband codecs
(e.g. G.722) the absolute MOS is approximate, but the trend and the relative
impact of loss/jitter remain informative; the codec is labelled so this is clear.

## Install for development

```bash
python3.10 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## External requirements

CallScope expects Wireshark command-line tools to be installed and on `PATH`:

- `tshark`
- `mergecap`

These are used for the heavy packet processing path (filtering, field
extraction, partial-capture extraction, and merging). `dpkt` is used only for
lightweight pcap metadata / fallback work, and `scapy` is a dev-only dependency.

## Basic usage

```bash
callscope siprec \
  --call-id "abc123@example.com" \
  --pcaps "/captures/*.pcap" \
  --out ./case-abc123
```

## TLS / SIP over TLS

If a TLS key log file is available:

```bash
callscope siprec \
  --call-id "abc123@example.com" \
  --pcaps "/captures/*.pcap" \
  --tls-keylog ./sslkeys.log \
  --out ./case-abc123
```

## Outputs

A successful run writes the following into the output directory:

- `recording-session.pcapng` — focused capture (SIP + RTP + RTCP)
- `report.html` — interactive, self-contained HTML troubleshooting report
- `summary.txt` — grep-friendly stable summary
- `summary.json` — machine-readable summary
- `siprec-metadata.json` — parsed SIPREC metadata
- `media-streams.json` — observed RTP/RTCP stream analysis
- `findings.json` — structured findings
- `escalation.md` — paste-ready escalation summary (plus timestamped copies)
- `rtcp-stats.json` — per-stream RTCP statistics
- `correlation-key.json` — time/AOR/5-tuple/SSRC key to join external systems

## Batch and baseline

Analyze many calls and emit an aggregate (failure rate + daily time series):

```bash
callscope batch --pcaps "/captures/*.pcap" --call-ids ./call-ids.txt --out ./batch
```

Capture a golden baseline from a known-good call, then diff a failing one:

```bash
callscope siprec --call-id good@sbc  --pcaps good.pcap  --out ./good --save-baseline ./baseline.json
callscope siprec --call-id bad@sbc   --pcaps bad.pcap   --out ./bad  --baseline ./baseline.json
```

## CLI options

```text
callscope siprec
  --call-id TEXT      Required. SIPREC Recording Session Call-ID.
  --pcaps TEXT        Required. File path, directory, or glob.
  --out PATH          Required. Output directory.
  --tls-keylog PATH   Optional. Wireshark/NSS TLS key log file.
  --keep-temp         Optional. Keep temporary extracted partial files.
  --verbose           Optional. Verbose logging.
  --no-html           Optional. Skip HTML report generation.
  --format TEXT       Optional. Output capture format: pcapng or pcap. Default: pcapng.
```

## Scope

v1 assumes SIPREC-side captures between SRC/SBC and SRS/recorder.
Full SBC-span correlation is planned for a later milestone.
