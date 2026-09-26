# AI-NIDS — Real-Time Network Intrusion Detection System

A machine-learning intrusion detection system that sniffs live network traffic,
scores every packet against a trained classifier, and streams the verdict to a
real-time web dashboard.

Two models are shipped pre-trained. The dashboard defaults to the **XGBoost**
engine, which scored **99.90%** accuracy on the held-out test set.

<!-- TODO: drop a screenshot of the dashboard here. It looks great on a profile. -->

---

## What it does

```
  Live NIC  ──►  Scapy sniffer  ──►  41 NSL-KDD feature extraction
                                            │
                                            ▼
                                 OneHot + RobustScaler
                                            │
                                            ▼
                                    XGBoost classifier
                                            │
                                            ▼
                          Socket.IO  ──►  Live dashboard
                                     (counters, chart, threat log)
```

- **Passive capture** — raw packet inspection with Scapy, no traffic is forwarded
  or modified.
- **Sliding-window features** — 2-second and 100-connection windows reproduce the
  statistical NSL-KDD features (`serror_rate`, `dst_host_count`, …) organically
  from live packets rather than replaying a static CSV.
- **Live dashboard** — Flask + Socket.IO push each verdict over a WebSocket to
  Chart.js counters, a real-time area chart, and a rolling attack log.

## Models

| Model | Accuracy | Notes |
|---|---|---|
| **XGBoost** | **99.90%** | Default engine in `ids_engine.py` |
| Random Forest | 99.81% | 100 trees; see `models/RandomForest/` |
| Ensemble Voting | — | Notebook included, no recorded results yet |

Trained on **NSL-KDD** (125,973 rows, 41 features + label).

## Project structure

```
.
├── ids_engine.py           # Flask app, Scapy sniffer, feature extraction, model inference
├── attack_simulator.py     # Test harness — generates real attack traffic (see warning below)
├── requirements.txt
├── .env.example            # Copy to .env; every value optional
├── models/
│   ├── XGBoost/            # xgb_model.pkl + scaler/encoder/label_encoder + notebook
│   ├── RandomForest/       # rf_model.pkl  + scaler/encoder/label_encoder + notebook
│   └── EnsembleVoting/     # ensemble_model.pkl + scaler/encoder/label_encoder + notebook
├── static/                 # style.css, script.js (Socket.IO client + Chart.js)
└── templates/index.html    # Dashboard markup
```

## Setup

Requires **Python 3.10+** and **Linux** (Scapy capture is POSIX-oriented).

```bash
git clone <your-fork-url>
cd AI-NIDS
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

The trained models are committed, so the dashboard runs immediately — no
training step and no dataset download required.

## Running

```bash
# 1. Find an interface that carries traffic
ip -br link

# 2. Point the engine at it
cp .env.example .env
nano .env          # set SNIFF_INTERFACE=youriface

# 3. Capture needs elevated privileges (raw sockets)
sudo python3 ids_engine.py
```

Then open **http://127.0.0.1:5000**.

The sniffer only inspects traffic from RFC1918 private ranges and ignores
broadcast/multicast, its own outbound traffic, and dashboard port 5000.

### Testing detection

`attack_simulator.py` generates SYN floods, ICMP floods, HTTP GET floods, and
FIN/XMAS port scans so you can watch the dashboard react. It requires `sudo` and
a target IP you control.

> ⚠️ **Authorized use only.** This sends genuine attack traffic. Run it *only*
> against a machine you own or a network you have explicit written permission to
> test. Attacking third-party systems is illegal in most jurisdictions.

## The dataset is not included

`nsl-kdd/` is gitignored. NSL-KDD is a **public** research dataset, but it is
~50MB, so it is not redistributed here. To retrain, download it from the
official NSL-KDD source and place `KDDTrain+.txt` at `./nsl-kdd/`, then open
any notebook in `models/` and run all cells. Notebooks expect that exact
relative path.

To retrain from scratch, delete the `.pkl` files in the model folder you want to
rebuild and re-run its notebook.

---

## Security notes

Please read before using or forking this repo.

**1. The `.pkl` files are pickles — `joblib.load()` executes code.**
Pickle deserialization is not a safe operation. These files are committed so the
project runs out of the box, and they were produced by the notebooks in this
repo from a public dataset. But if you fork this project, treat any `.pkl` that
did *not* come from these notebooks as untrusted: loading it could execute
arbitrary code on your machine. The safe path is to delete them and retrain.
Loading is restricted to the XGBoost folder in `ids_engine.py`.

**2. No secrets are committed.** The Flask `SECRET_KEY` is read from the
environment and falls back to a randomly generated per-run key, so no credential
is ever stored in version control. `.env` is gitignored; only `.env.example` is
tracked. No API keys, tokens, passwords, or credentials exist in this repo.

**3. No captured traffic is committed.** The dashboard displays real source and
destination IPs from whatever network the engine is attached to at runtime. No
packet captures, logs, or traffic data are stored in this repository, and
`*.pcap` / `*.log` / `capture/` are gitignored to keep it that way.

**4. The dashboard is unauthenticated and binds to `0.0.0.0`.** By default it
listens on all interfaces, so anyone on the same network can view live traffic
metadata. That is fine on an isolated lab network, but do not expose it to an
untrusted network or the public internet. If you need LAN access deliberately,
firewall port 5000 to specific hosts.

**5. Running the engine requires `sudo`** for raw socket capture. Treat that
privilege as the real security boundary — run it on a host where root is not
more powerful than the task requires.

## Viewing terms

This project is published for **viewing and reference only**. It is not
open-licensed: no license is granted to copy, redistribute, or commercially
reuse it. All rights reserved.

Third-party components and data retain their own licenses — notably
[NSL-KDD](https://www.unb.ca/cic/datasets/nsl-kdd.html), which is not
distributed here.
