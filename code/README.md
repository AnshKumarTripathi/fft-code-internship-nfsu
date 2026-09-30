# Log Anomaly Detection Pipeline

Python batch pipeline for log anomaly detection and attack reconstruction (NFSU FFT project). Implementation follows `ground_truth_log_anomaly_sdd.md` at the repository root; **do not edit that file** for implementation convenience.

This directory (`code/`) is the runnable project root. Phase 9/17/43 writes incident Markdown and HTML under `data/reports/`. The **product investigation UI** is Next.js in [`../web/`](../web/) (port 3000) against this FastAPI JSON API (`/api/v1`, port 8000). Optional Jinja on :8000 is **legacy** (`dashboard.serve_legacy_html: true`). **Versions seven through ten are Complete** (Phases **56–86**): Pipeline UI, analyses, Docs, coverage catalogue + normalize + Track B dialects — [version ten](../docsm/version_ten/overall_plans.md). Inventory: [log_coverage.md](../docsm/version_ten/log_coverage.md). Predecessor Docs: [version nine](../docsm/version_nine/overall_plans.md).

## Version three (frozen) — multi-family ingest

v3 is **multi-family ingest**. Detectors, correlate, report, and extractors are unchanged from v2/v3. **No authentication** (bind localhost; local trusted network only). Phase 53 ML paths: default IsolationForest; opt-in `autoencoder` or working `onnx` (`.onnx` + `.vocab.json`). **v3 families are unchanged; v4/v5 add no new `log_source`.** The product UI is Next.js in [`../web/`](../web/). See [version five](../docsm/version_five/overall_plans.md) and [version six](../docsm/version_six/overall_plans.md).

Stable `log_source` names are listed below (**146** registered; authority also [`docsm/version_ten/log_coverage.md`](../docsm/version_ten/log_coverage.md)). Put text/JSON/CSV/CEF exports under `data/raw/` (or enable `normalize` for archives / `.evtx` / `.journal` — Phases **80–81**). **Not any-log:** unmatched lines fail extraction and are skipped at parse. A three-family drop-in lives at `tests/fixtures/logs/mixed_v3/` (`ssh`, `windows_security`, `firewall`). That corpus is short: `run-all` will ingest/parse/bucket and typically soft-skip correlate/report. Use `run-all --require complete` only on a long-history lab corpus.

Phase 19 adds the nearest Linux auth family next to SSH. Phase 20 adds Windows Event Log families (one-line wevtutil / Get-WinEvent text; **not** binary `.evtx`) plus Phase **85** classic **`pfirewall.log`** (`windows_pfirewall`). Phase 21 adds the rest of Linux/Unix OS logs plus macOS. Phase 22 adds remaining identity sources (LDAP, RADIUS/TACACS+, IdP, MFA, MIT KDC, Vault). Phase 23 adds network infrastructure (pfSense filterlog, **iptables/UFW** (Phase 85), Cisco IOS, OpenVPN, BIND, dhcpd, Squid, nfdump, HAProxy, Cisco ISE, hostapd, FRR bgpd). Phase 24 adds security appliances (Suricata EVE JSON, **Snort fast alert** (Phase 82), ModSecurity JSON, ClamAV, cowrie, Cuckoo-like sandbox). Phase **83** adds Zeek / Bro TSV (`zeek_conn`, `zeek_dns`). Phase **84** adds ArcSight **CEF** (`cef`). Live EDR APIs and multi-line Nessus XML remain stretch. Phase 25 adds application and web logs (Apache/Nginx combined access, IIS W3C, error_log, JSON runtime, Kong file-log). AWS API Gateway belongs in Phase 27. Phase 26 adds database engines (PostgreSQL stderr, MySQL general/slow, SQL Server errorlog, Oracle alert, MongoDB JSON, Cassandra system.log text, Redis server log). `raw_fields.event_class` is one of `query` / `slow` / `audit` / `wal` / `replication` / `session` / `ddl` / `backup` / `procedure`. Redis **as datastore** is `db_redis`; cache-shaped `MONITOR` files may become Phase 31 `cache`. Phase 27 adds cloud and SaaS **file exports** (JSON Lines / one-line text; **not** live AWS/Azure/GCP APIs). CloudTrail is one event object per line (optional compact `Records` wrapper). Pretty-printed multi-line CloudTrail dumps are not expanded. AWS API Gateway is not a separate `log_source` (Kong remains `api_gateway`). Phase 28 adds container and orchestration **file exports** (`docker logs`, `kubectl logs`, audit JSON; **not** live cluster clients). Dialects are JSONL or one text line. Istio Envoy `outbound|` is `service_mesh` (not Squid `proxy`). CRI pod stdout is `k8s_pod` (not Apache `web_access`). `dockerd[` is `docker` (not generic `linux_syslog`). `audit.log` stays `linux_auditd`.

| `log_source` | Meaning |
|---|---|
| `ssh` | OpenSSH / `sshd` (v2 + remainder patterns) |
| `linux_pam` | PAM that is **not** `pam_unix(sshd:)` |
| `linux_auth` | sudo / su / login on `auth.log` / `secure` |
| `linux_wtmp` | `last` / `utmpdump` text (not binary wtmp) |
| `windows_security` | Security Event Log, including Kerberos/NTLM Event IDs |
| `windows_system` | System Event Log |
| `windows_application` | Application Event Log |
| `windows_setup` | Setup Event Log |
| `windows_forwarded` | Forwarded Events |
| `windows_powershell` | PowerShell operational / transcription |
| `windows_defender` | Windows Defender |
| `windows_task_scheduler` | Task Scheduler |
| `windows_wmi` | WMI activity |
| `windows_gpo` | Group Policy operational |
| `windows_print` | Print Service |
| `windows_firewall` | Windows Filtering Platform / Windows Firewall **Event Log** text |
| `windows_pfirewall` | Classic Windows **`pfirewall.log`** file (`#Fields` + DROP/ALLOW; Phase 85). Not Event Log `windows_firewall` |
| `windows_bitlocker` | BitLocker / recovery |
| `windows_rdp` | RDP / Terminal Services |
| `windows_ad` | Directory Service / AD FS text that is not a Security Event ID |
| `linux_syslog` | RFC3164/RFC5424 that is not SSH/PAM/sudo/kern/cron |
| `linux_kern` | `kern.log` — syslog header **plus** `kernel:` |
| `linux_dmesg` | `dmesg -T` or `[seconds.nsec]` (no syslog host header) |
| `linux_journald` | `journalctl` short text / `_SYSTEMD_UNIT=` (not binary journal) |
| `linux_cron` | syslog `CRON[` |
| `linux_package` | **dpkg.log** one-liners (not multi-line apt `history.log`) |
| `linux_auditd` | ausearch `type=USER_AUTH` / `USER_LOGIN` / `SYSCALL` |
| `linux_boot` | `boot.log` `[  OK  ]` / `[FAILED]` |
| `linux_mac` | SELinux `avc: denied` / AppArmor `DENIED` |
| `macos_unified` | `log show` default text |
| `macos_asl` | ASL `[Time …] [Sender …]` |
| `macos_install` | Installer/`PackageKit` or DiagnosticReports `Date/Time:` |
| `ldap` | OpenLDAP `slapd` BIND/RESULT (not generic syslog) |
| `radius` | FreeRADIUS Accept/Reject; `tac_plus` stays this source |
| `idp` | Okta System Log JSON (`eventType`); not Azure AD |
| `mfa` | Duo Admin JSON or syslog `duo` |
| `kerberos_kdc` | MIT `krb5kdc` `AS_REQ`/`TGS_REQ` (not Windows Event 4768) |
| `vault` | HashiCorp Vault JSON audit |
| `firewall` | pfSense **filterlog** allow/deny / NAT (not `windows_firewall`; not `iptables`) |
| `iptables` | UFW / iptables LOG / simple nftables syslog (`[UFW BLOCK]` / `SRC=` `DST=`; Phase 85). Not pfSense `firewall` |
| `network_device` | Cisco IOS `%LINEPROTO` / `%SEC-6-IPACCESSLOGP` |
| `vpn` | OpenVPN `openvpn[` TLS username / peer |
| `dns` | BIND `named[` client query log |
| `dhcp` | ISC **dhcpd** lease syslog |
| `proxy` | Squid combined (`TCP_MISS` / `TCP_DENIED`; not Apache/Nginx; not Istio mesh) |
| `netflow` | nfdump text `date flow` |
| `load_balancer` | HAProxy HTTP log (on-prem; not cloud ELB) |
| `nac` | Cisco ISE `CISE_Passed_Authentications` / `CISE_Failed_Attempts` |
| `wireless` | hostapd association / deauth |
| `bgp` | FRR `bgpd[` `%ADJCHANGE` neighbor up/down |
| `ids_ips` | Suricata **EVE JSON** (`event_type` + `src_ip`) **or** Snort **fast alert** text (`[**]` / `{TCP}` →); `raw_fields.dialect` = `suricata_eve` \| `snort_fast`. Not Zeek; not `firewall` |
| `zeek_conn` | Zeek / Bro **conn.log** TSV (`#fields` header; entity = `id.orig_h`; Phase 83). Not Squid `proxy`; not Suricata/Snort `ids_ips` |
| `zeek_dns` | Zeek / Bro **dns.log** TSV (`query` in `raw_fields`; Phase 83). Not BIND `dns` |
| `waf` | ModSecurity **JSON** `transaction` (not Apache/Nginx access) |
| `dlp` | generic JSON `policy` / `user` / `action` |
| `edr` | CrowdStrike-like JSON `event_simpleName` (file export; not live API) |
| `antivirus` | ClamAV `FOUND` / `clamd[` (not `windows_defender`) |
| `vuln_scanner` | one JSON finding (`pluginID` / `host` / `severity`; not `.nessus` XML) |
| `siem` | generic JSON correlated export (`rule_name`) |
| `honeypot` | cowrie JSON (`eventid` starts with `cowrie.`) |
| `sandbox` | Cuckoo-like JSON (`malscore`; hash as `service` if no host) |
| `threat_intel` | STIX/JSON indicator `accepted` / `rejected` |
| `cef` | ArcSight **CEF** text (`CEF:0\|Vendor\|Product\|…\|ext`); entity prefers `suser` then `src`; Phase 84. Not JSON `siem` |
| `web_access` | Apache **combined**, Nginx combined, IIS **W3C** (`src_ip`/`status`/`method`/`path`) |
| `web_error` | Nginx `YYYY/MM/DD [error]` and Apache `[Wed Jan 15 …] [client ip]` |
| `app_runtime` | JSON `ts`/`level`/`msg` (not k8s pod stdout unless CRI-prefixed) |
| `app_exception` | timestamped Python/Java traceback **header** (not full stack reconstruction) |
| `api_gateway` | Kong **file-log JSON** (`latencies` / `client_ip`; not AWS API Gateway) |
| `api_audit` | JSON `method`/`path`/`status`/`actor` |
| `feature_flag` | JSON `flag`/`user`/`action` (not DLP `policy`) |
| `apm` | span JSON `traceId`/`duration` |
| `db_postgres` | PostgreSQL stderr `%m [%p] %u@%d` (`event_class` in `raw_fields`) |
| `db_mysql` | MySQL/MariaDB general + slow file text (not RDS) |
| `db_mssql` | SQL Server **errorlog** text (`spidNN`; not Windows Event Log) |
| `db_oracle` | Oracle **alert log** (`ORA-` / `RMAN-`) |
| `db_mongodb` | MongoDB JSON `t`/`s`/`c`/`id`/`attr` (not `app_runtime`) |
| `db_cassandra` | Cassandra system.log text (`Native-Transport-Requests`; not `system.log` filename) |
| `db_redis` | Redis server log + MONITOR/ACL as **datastore**. Cache-shaped `MONITOR` files (`monitor.log`) or memcached verbose are Phase 31 `cache` |
| `aws_cloudtrail` | CloudTrail JSONL (`eventSource`/`eventName`/`userIdentity`; optional compact `Records`) |
| `aws_vpcflow` | VPC Flow v2 text (`eni-` + ACCEPT/REJECT) |
| `aws_s3` | S3 server access log (`REST.GET.OBJECT`) |
| `aws_elb` | ALB access (`h2`/`http` + `app/`; not HAProxy) |
| `aws_guardduty` | GuardDuty finding JSON |
| `aws_config` | Config item JSON (`configurationItem`) |
| `aws_lambda` | CloudWatch `START`/`REPORT RequestId:` |
| `aws_rds` | RDS Postgres `UTC:ip(port):user@db:[pid]:` (not local `db_postgres`) |
| `azure_activity` | Activity Log JSON (`caller` + `operationName`) |
| `azure_ad` | signInLogs / auditLogs JSON (not Windows Event ID) |
| `azure_nsg` | NSG `flowTuples` JSON |
| `azure_monitor` | Monitor diagnostic JSON |
| `azure_keyvault` | Key Vault `AuditEvent` JSON |
| `gcp_audit` | Cloud Audit JSON (`cloudaudit.googleapis.com`) |
| `gcp_iam` | Cloud Audit `SetIamPolicy` (`event_class=iam`) |
| `gcp_vpcflow` | GCP VPC flow JSON (`jsonPayload.connection`) |
| `gcp_lb` | HTTP(S) LB JSON (`httpRequest.remoteIp`) |
| `casb` | generic JSON `user`/`app`/`action` (not DLP `policy`) |
| `saas_workspace` | Admin SDK activity JSON (`kind: admin#reports#activity`) |
| `saas_m365` | Unified Audit Log JSON (`Workload`/`Operation`/`UserId`) |
| `saas_salesforce` | EventLogFile-like JSON (`EVENT_TYPE`/`USER_ID_DERIVED`) |
| `docker` | Docker daemon syslog `dockerd[` or json-file `log`/`stream`/`time` |
| `k8s_audit` | Kubernetes audit JSON (`audit.k8s.io`; user or service account) |
| `k8s_apiserver` | kube-apiserver klog / syslog |
| `k8s_kubelet` | kubelet klog / syslog |
| `k8s_scheduler` | kube-scheduler klog / syslog |
| `k8s_pod` | CRI `kubectl logs` (`stdout`/`stderr F\|P`; not Apache combined) |
| `k8s_admission` | AdmissionReview JSON or admission webhook klog |
| `service_mesh` | Istio Envoy access (`outbound\|` / `istio`; not Squid `proxy`) |
| `helm` | Helm stdout (`helm install` / `Release "…"` ) |
| `container_registry` | registry JSON pull/push or nginx `"GET /v2/` (not generic `access.log`) |
| `smtp` | Postfix `smtpd`/`smtp` syslog (not `qmgr`) |
| `mail_gateway` | rspamd / spamd syslog or JSON |
| `mta` | Postfix `qmgr`/`pickup`/`cleanup` or Exchange tracking |
| `dmarc` | OpenDMARC / OpenDKIM syslog |
| `collab_audit` | Slack / Teams / Zoom audit JSON (`actor`/`action`/`workspace`) |
| `cicd_build` | Jenkins / GitHub Actions / GitLab job JSON / CircleCI |
| `cicd_deploy` | deploy JSON `event=deploy` (not Terraform `iac`) |
| `artifact_repo` | Nexus `/repository/` or Artifactory |
| `vcs_audit` | git `received-pack` / Gitea-GitLab audit JSON |
| `package_resolve` | npm / pip / maven resolve |
| `image_scan` | Trivy / Grype JSON (`Vulnerabilities`; not registry pull) |
| `kafka` | Kafka `server.log` / controller (`[KafkaServer` / `GroupCoordinator`) |
| `rabbitmq` | RabbitMQ connection/channel (`user '…' authenticated`) |
| `esb` | JSON `tx_id` + `route` |
| `cache` | Redis/Memcached **cache** commands: filename `monitor.log` / marker `MONITOR` / memcached verbose. Redis **server** logs stay `db_redis` |
| `airflow` | Airflow task/scheduler (`taskinstance.py` / `DAG:`; not `linux_cron`) |
| `hypervisor` | ESXi `Hostd` / Hyper-V-VMMS / KVM `libvirtd[` (not `docker`) |
| `san` | array syslog `LUN` / `volume` |
| `backup` | Veeam / Commvault / Bacula `Job finished` |
| `ntp` | `ntpd[` / `chronyd[` syslog (not generic `linux_syslog`) |
| `license` | FlexLM-like `OUT` / `IN` / `DENIED` |
| `config_mgmt` | Ansible `PLAY RECAP` / `TASK [`, Puppet report, Chef Client |
| `iac` | Terraform `Apply complete` / `@module=terraform.ui` (not `cicd_deploy`) |
| `badge` | CSV `ts,badge_id,door,result` or syslog `badge_id=`/`door=` (entity is badge ID as `user`; allow/deny → `auth_result`) |
| `cctv` | JSON `camera_id` + `event` (`motion`/`offline`; camera as `host`) |
| `bms` | syslog/JSON `panel`/`zone`/`alarm` (not generic syslog) |
| `iot` | JSON `device_id` + `fw_version` or firmware `event` (device as `host`) |
| `ics` | syslog/JSON `plc` + `tag`/`value` (PLC as `host`) |
| `voip` | Asterisk / Kamailio syslog `INVITE` / `REGISTER` + `sip:` (user or IP; REGISTER fail → `auth_result`) |
| `pbx` | CSV CDR `src,dst,duration,disposition` (src extension as `user`) |
| `video_conf` | JSON `meeting_id` + `organizer`/`join` (call logs; Zoom/Teams **audit** stays `collab_audit`) |
| `ivr` | JSON `call_id` + `menu`/`agent` (agent as `user`, else menu as `service`) |
| `pki_ca` | CFSSL/step-ca JSON or syslog `issued`/`revoked` + `cn=` (CN as `service`; `action` issued/revoked) |
| `hsm` | syslog/JSON `slot` + `op` (user or host) |
| `tls` | nginx `ssl_handshake` / OpenSSL `s_server` (not combined `web_access`) |
| `ct_log` | JSON `domain` + `issuer` + `event` (`seen`/`misissue`; domain as `host`) |
| `code_signing` | JSON `hash` + `signer` + `result` (signer as `user`) |

Restrict a lab to SSH with:

```yaml
ingestion:
  enabled_sources: [ssh]   # empty list = all registered families
```

Copy `tests/fixtures/logs/mixed_v3/` into `data/raw/` for a mixed SSH + Windows Security + pfSense parse. With `enabled_sources: [ssh]`, only `ssh` rows land in `parsed_events`.

### Demo corpus (full pipeline + UI)

The short `mixed_v3` corpus cannot satisfy detector cold-start (72h spectral, 24 statistical windows, 20 ML hours, 20 cluster peers). Generate a **35-day lab corpus** locally:

```bash
cd code
python scripts/generate_demo_corpus.py
python -m src.pipeline run-all --config config/pipeline.yaml --require complete
```

Output lands in `data/raw/demo_corpus/` (gitignored). The generator writes eight multi-source files (SSH, app runtime JSONL, Windows Security, CloudTrail, badge CSV) plus `manifest.json` documenting attack windows and expected detectors.

After `run-all`, start the investigation UI:

```bash
cd ../web && npm run dev
```

Optional evaluation labels: `tests/fixtures/labels/demo_eval.csv` — set `evaluation.labels_path` in `config/pipeline.yaml`, then `python -m src.pipeline evaluate --config config/pipeline.yaml`.

| Entity | Role |
|---|---|
| `alice` | Statistical rate burst (day 29) |
| `web-01` | Spectral shape change + energy burst (host entity → critical severity) |
| `bob` | ML rare-template hour (day 31) |
| `outlier-01` | Cluster outlier (8h rhythm vs 24h peers) |
| `peer-01`…`peer-20` | Cluster peer baseline |
| `charlie` | Benign negative control |

Analyst actions (dismiss / note / reopen) are **not** pre-seeded — add them live in the UI for workflow demos.

| Topic | Where |
|---|---|
| `evaluate` / `--cold-start-synthetic` | [Evaluate](#evaluate-phase-15) |
| Threshold calibration (`calibrate_thresholds.py`) | [Threshold calibration](#threshold-calibration-phase-50) |
| `run-all --require complete` | [CLI](#cli) |
| `ingestion.syslog_year_policy`, `dedup_memory_max_hashes`, `enabled_sources` | [Ingest](#ingest) |
| Incident triage filters / KPIs / open queue | [Investigation UI](#investigation-ui) |
| `correlation.promotion` (ensemble) | [Correlate](#correlate) |
| `correlation.incident_gap_minutes`, `ip_link_horizon_hours`, cluster window | [Correlate](#correlate) |
| `detect-changepoint` (CUSUM) | [Detect changepoint](#detect-changepoint) |
| `detect-seasonal` (residual) | [Detect seasonal](#detect-seasonal) |
| `ml.flagging` (`mad_threshold` default vs `predict`) | [Detect ML](#detect-ml) |
| Investigation UI (Next.js `../web/`, port 3000) | [Investigation UI](#investigation-ui) |
| JSON `/api/v1`, CORS, optional legacy Jinja | [Investigation UI](#investigation-ui) |
| JSON `/api/*` aliases, `/health` vs `/health/ready`, warehouse 503 | [JSON API](#json-api-always-on) |
| Spectral coupling (`bucket_seconds` ↔ `window_hours`) | [Detect spectral](#detect-spectral) |
| Why **4.0**, dual OR, known FPs/FNs, promotion | [`../KNOWN_LIMITATIONS.md`](../KNOWN_LIMITATIONS.md) |
| Notebook | `notebooks/exploratory_analysis.ipynb` |

## Requirements

- Python **3.11+**
- Run all commands from this `code/` directory so relative paths in `config/pipeline.yaml` resolve correctly.

## Setup

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

## Data layout

| Path | Role |
|---|---|
| `data/raw/` | **Read-only** input corpus drop — the pipeline must never rewrite source logs |
| `data/raw/uploads/` | Operator upload landing zone (`pipeline_ui.upload_dir`) |
| `data/raw/normalized/` | Phase 80 normalize output (archives expanded / passthrough copies); ingest may point here after normalize |
| `data/raw/normalize_dead_letter/` | Phase 80 unsupported / failed archives (`dead-letter.jsonl`) |
| `data/raw/shards/` | Phase 88 line-safe shard output (`<run_id>/*.shardNNNNN.log` + `manifest.jsonl`) |
| `data/parsed/ingest_staging/` | Phase 2 Parquet staging (internal; consumed by `parse`) |
| `data/parsed/events/event_date=YYYY-MM-DD/` | Phase 3 `parsed_events` Parquet (hive partitions) |
| `data/baselines/drain3_state.bin` | Live Drain3 TemplateMiner state (mutates on `train_and_snapshot`) |
| `data/baselines/snapshots/parse/<id>/` | Frozen Drain3 state for `parse.mode: reuse_snapshot` |
| `data/baselines/snapshots/ml/<id>/` | Frozen IsolationForest (`isolation_forest.pkl`) or autoencoder (`autoencoder.pkl`) for `ml.mode: reuse_snapshot` |
| `data/timeseries/entity_id=<id>/` | Phase 4 `entity_bucket_counts` Parquet (hive partitions) |
| `data/scores/statistical/entity_id=<id>/` | Phase 5 `statistical_window_scores` Parquet (hive partitions) |
| `data/scores/spectral/entity_id=<id>/` | Phase 6 `spectral_window_scores` Parquet (hive partitions) |
| `data/scores/ml/entity_id=<id>/` | Phase 7 `ml_window_scores` Parquet (hive partitions) |
| `data/reports/` | Phase 9/17 incident reports (`incident_<id>.md` and `incident_<id>.html`) |
| `data/reports/eval/` | Phase 15 metrics (`metrics.json`, `metrics.md`) + Phase 50 calibration (`calibration.json`, `calibration.md`) |
| `data/warehouse.duckdb` | DuckDB query warehouse (created on first `get_connection()`; not committed) |
| `notebooks/exploratory_analysis.ipynb` | Phase 18 read-only warehouse exploration (run from `code/`) |

## Investigation UI

**Investigation UI:** Next.js (`../web/`, port **3000**).  
**API:** FastAPI (`code/`, port **8000**), `/api/v1`.  
**Operator pipeline (v7/v8):** **Pipeline** is the home page at `http://127.0.0.1:3000/` (upload / stage, start `run-all`, stage progress; single-flight; busy → HTTP 409). `/pipeline` redirects to `/`. Triage (incident queue) is at `/incidents`. **In-app Docs (v9):** `http://127.0.0.1:3000/docs` — operator/mentor manual (static; works if the API is down). CLI `python -m src.pipeline run-all` remains the power-user path; Node is **not** required for batch stages themselves. Upload caps: `pipeline_ui` in `config/pipeline.yaml` (default **50 MiB** / file, **50** files / request). See [`KNOWN_LIMITATIONS.md`](../KNOWN_LIMITATIONS.md) §4.1–4.2 and [version nine](../docsm/version_nine/overall_plans.md).
**Legacy Jinja:** set `dashboard.serve_legacy_html: true` in `config/pipeline.yaml`.  
**No authentication** — bind the API to localhost; do not expose port 8000 on a hostile network.  
v3 log families are unchanged; v4–v7 add no `log_source` values. Product plan: [version seven](../docsm/version_seven/overall_plans.md) (**Complete**).

Two terminals:

```bash
# terminal 1 — API (from code/)
pip install -r requirements-api.txt
uvicorn src.api.main:app --host 127.0.0.1 --port 8000

# terminal 2 — UI (from web/)
npm install
npm run dev -- --port 3000
```

Open `http://127.0.0.1:3000`. Optional: set `PIPELINE_CONFIG` to an alternate `pipeline.yaml`. Copy `web/.env.local.example` to `web/.env.local` (`NEXT_PUBLIC_API_BASE=http://127.0.0.1:8000`). Helper: [`../scripts/dev-v4.ps1`](../scripts/dev-v4.ps1) / [`../scripts/dev-v4.sh`](../scripts/dev-v4.sh) starts uvicorn and prints the Next command.

**CORS:** `dashboard.cors_origins` in `config/pipeline.yaml` (default `http://127.0.0.1:3000` and `http://localhost:3000`). Never `*`. If Next is not on those origins, add the origin here and restart uvicorn.

Default `serve_legacy_html: false` — `GET /` on port 8000 is **not** the incidents table; it tells you to use Next on port 3000. JSON `/api/v1/*`, unversioned `/api/*` aliases, and `/health` stay on regardless of the flag.

**Triage (Phases 47–49):** Home incident list filters by date range, `detector` (multi), `disposition` (`open` / `dismissed` / `any`), `min_detectors`, severity, entity, `q`, and sort — all URL-round-trippable. Home KPIs link to pre-filtered lists (open queue). Entity/incident analysis charts support zoom/pan; PSD primary axis is **period hours**. Overlay toggles do not remove the count series. **STFT heatmap (Phase 60):** disclosure on analysis pages; `GET /api/v1/entities/{id}/stft` capped at 128×200.

## JSON API (always on)

Read-only JSON over `data/warehouse.duckdb`. Install API extras separately so pipeline stages stay lean:

```bash
pip install -r requirements-api.txt
uvicorn src.api.main:app --host 127.0.0.1 --port 8000
```

**D14 path split:** the SDD’s `GET /incidents` is **JSON at `/api/incidents`** (v2 alias) and **`/api/v1/incidents`** (envelope). HTML investigation pages are Next, not FastAPI, unless legacy Jinja is enabled.

| Route | Role |
|---|---|
| `GET /api/v1/incidents` | Envelope of incidents (`items`, `total`, `limit`, `offset`). Filters: `severity`, `entity_id`, `q`, `start_after`, `end_before`, `detector` (repeatable or CSV), `min_detectors`, `disposition` (`open`\|`dismissed`\|`any`), `sort` (`severity`\|`start_time`\|`anomaly_count`), `order` (`asc`\|`desc`) |
| `GET /api/v1/incidents/{id}` | Incident + anomalies + `actions` (R9) |
| `GET /api/v1/incidents/{id}/timeline` | Reconstruction events (`log_source`) |
| `GET /api/v1/incidents/{id}/edges` | Correlation edges |
| `GET /api/v1/incidents/{id}/actions` | Append-only analyst action history |
| `POST /api/v1/actions` | Dismiss / note / reopen (warehouse row; undo is reopen, not delete) |
| `GET /api/v1/entities` | Entity search (`?q=`) |
| `GET /api/v1/entities/{id}` | Entity meta |
| `GET /api/v1/entities/{id}/timeline` | Event timeline |
| `GET /api/v1/entities/{id}/spectrum` | Spectral features + PSD |
| `GET /api/v1/entities/{id}/stft` | Capped STFT power matrix (Phase 60 heatmap) |
| `GET /api/v1/entities/{id}/buckets` | Activity buckets + overlays |
| `GET /api/v1/kpis` | Severity counts + last correlate |
| `GET /api/v1/ui-policy` | Display cutoffs + default `operator_label` |
| `GET /api/v1/runs` | `pipeline_runs` |
| `POST /api/v1/pipeline/jobs` | Start background `run-all` (single-flight; 409 if busy) |
| `GET /api/v1/pipeline/jobs` / `{job_id}` | Latest / poll job status |
| `POST` / `GET` / `DELETE /api/v1/pipeline/uploads` | Stage logs under `pipeline_ui.upload_dir` |
| `POST /api/v1/pipeline/corpus/demo` | Copy mixed_v3 fixtures into uploads |
| `GET /api/v1/reports` | Report file list |
| `GET /api/v1/reports/{filename}` | FileResponse (`incident_*.md` / `.html`, path-traversal guarded) |
| `GET /api/incidents` | v2 JSON alias (bare list) |
| `GET /health` | Liveness `{status: ok, db: not_checked}` (does not open DuckDB) |
| `GET /health/ready` | Readiness `{status, db}` (opens warehouse read-only) |

**Ops notes:** bind localhost by default; **no authentication** — local trusted network only. Prefer a completed batch (Pipeline UI or CLI `run-all` through correlate/report) before opening the triage views. If a writer (`python -m src.pipeline …` or an in-process Pipeline job) holds the warehouse, JSON returns **503** instead of a traceback — wait for the job to finish, then retry.

### Legacy Jinja (optional)

Set `dashboard.serve_legacy_html: true` to serve Phase 16 HTML on port 8000 (`/`, `/incidents/{id}`, `/entities`, `/runs`, `/reports`). Chart.js stays vendored under `src/api/static/vendor/` for that mode. Templates are not deleted.

## Ingest

**Normalize first (Phase 80–81, opt-in):** set `normalize.enabled: true` to expand archives and decode `.evtx` / `.journal` from `pipeline_ui.upload_dir` into `normalize.output_dir` (`data/raw/normalized/` by default). Locked EVTX dialect: one-line `TimeCreated=… EventID=…` text via **python-evtx**. Journal: `journalctl --file=… -o short-iso` (Linux). Caps and dead-letter: [`KNOWN_LIMITATIONS.md`](../KNOWN_LIMITATIONS.md) §4.5.

**Large-corpus split (v11 Complete, Phases 88–92, opt-in):** oversized **on-disk** text logs can be split line-safe then sequentially ingested/parsed into **one** warehouse, then **one** detect/correlate on the merged series. Soft targets `sharding.target_shard_bytes` (default 1 GiB) and/or `target_shard_lines`; hard stop `max_shards` (500). Drain3: first shard `train_and_snapshot`, later shards `reuse_snapshot`. Soft-skips (cold start, STFT cap, empty correlate) still apply on the **merged** history. Optional `sharding.analysis_window` bounds heavy detectors to last W days (or absolute UTC) without deleting warehouse rows. Default `sharding.enabled: false` leaves small labs unchanged. With `sharding.enabled: true`, Pipeline UI offers server-path / one staged file, `i/N` progress, and cancel-between-shards. Caps: [`KNOWN_LIMITATIONS.md`](../KNOWN_LIMITATIONS.md) §4.6.

```bash
python -m src.pipeline shard-split --config config/pipeline.yaml --input path/to/huge.log
python -m src.pipeline run-sharded --config config/pipeline.yaml --through report --input path/to/huge.log
# debug stop after parse: --through parse
# or: --manifest data/raw/shards/<run_id>/manifest.jsonl
```
Drop SSH, Linux auth-style, Windows Event Log text, Unix OS remainder, macOS text, identity, and network infrastructure logs under `data/raw/` (or under `normalized/` after an enabled normalize run). **Phase 19** accepts `ssh`, `linux_pam`, `linux_auth`, and `linux_wtmp`. **Phase 20** accepts the `windows_*` sources above. **Phase 21** accepts `linux_syslog` / `linux_kern` / `linux_dmesg` / `linux_journald` / `linux_cron` / `linux_package` / `linux_auditd` / `linux_boot` / `linux_mac` and `macos_*`. **Phase 22** accepts `ldap` / `radius` / `idp` / `mfa` / `kerberos_kdc` / `vault`. **Phase 23** accepts `firewall` / `network_device` / `vpn` / `dns` / `dhcp` / `proxy` / `netflow` / `load_balancer` / `nac` / `wireless` / `bgp`. Windows dialect is **one event per line** (`EventID=` / `Id:` and `TimeCreated` on the same line). Flatten multi-line Format-List dumps before dropping them; **do not** drop binary `.evtx` / `.journal` without `normalize.enabled: true` (Phase 81 adapters). `linux_kern` has a syslog header plus `kernel:`; `linux_dmesg` does not. Package dialect is **dpkg.log**, not apt `history.log`. Identity: OpenLDAP **slapd** (not generic syslog); Okta System Log JSON (not Azure AD); MIT `krb5kdc` (not Windows Event 4768); Vault JSON audit. Network: pfSense **filterlog** (not Windows Event 5156/5157); Cisco IOS `%LINEPROTO`/`%SEC`; OpenVPN (not IdP SSO); BIND query log; ISC dhcpd; Squid combined (not Apache/Nginx); nfdump text; HAProxy HTTP (not cloud ELB); Cisco ISE `CISE_*` (not FreeRADIUS `Access-Accept`); hostapd; FRR `bgpd`. **Phase 24** accepts `ids_ips` / `waf` / `antivirus` / `honeypot` / `sandbox` (and siblings). **Phase 25** accepts `web_access` / `web_error` / `app_runtime` / `api_gateway`. **Phase 26** accepts `db_postgres` / `db_mysql` / `db_mssql` / `db_oracle` / `db_mongodb` / `db_cassandra` / `db_redis`. **Phase 27** accepts `aws_cloudtrail` / `aws_vpcflow` / `aws_s3` / `aws_elb` / `aws_guardduty` / `aws_config` / `aws_lambda` / `aws_rds` / `azure_*` / `gcp_*` / `casb` / `saas_*` from **exported files** (JSONL / one-line text; no cloud SDKs). ALB is `aws_elb` (not HAProxy `load_balancer`); RDS Postgres prefix is `aws_rds` (not `db_postgres`); Azure AD JSON is `azure_ad` (not Windows Event Log). **Phase 28** accepts `docker` / `k8s_audit` / `k8s_apiserver` / `k8s_kubelet` / `k8s_scheduler` / `k8s_pod` / `k8s_admission` / `service_mesh` / `helm` / `container_registry` from **exported files** (JSONL / one-line text; no cluster clients). Istio `outbound|` is `service_mesh` (not `proxy`); CRI pod stdout is `k8s_pod` (not `web_access`); `dockerd[` is `docker` (not `linux_syslog`); `audit.log` stays `linux_auditd`. Database `raw_fields.event_class` is `query` / `slow` / `audit` / `wal` / `replication` / `session` / `ddl` / `backup` / `procedure`. Mongo JSON uses `t`/`s`/`c`/`id` (not `app_runtime` `ts`/`level`/`msg`); Cassandra text is `cassandra.txt` / `cassandra.log` (never `system.log`); Redis as datastore is `db_redis` (Phase 31 may add `cache`). Source tagging is **content-first** (`sshd[` wins over generic `session opened`; `avc: denied` is `linux_mac` not generic syslog; `slapd[` is `ldap` not `linux_syslog`; `filterlog[` is `firewall` not `linux_syslog`; Windows `EventID` never steals SSH; weak `ALLOW`/`deny`/`from` never steal SSH; Mongo `c`+`id` wins over `app_runtime`; CloudTrail JSON wins over generic app JSON; `haproxy[` stays `load_balancer`; mesh `outbound|` wins over `proxy`) with **filename fallback** (`auth` / `secure` / `sshd` / `ssh` / `openssh` → `ssh`; `pam.log` → `linux_pam`; `wtmp` / `btmp` / `last.log` → `linux_wtmp`; `audit.log` → `linux_auditd`; `ldap.log` / `okta.json` / `duo.log` / `krb5kdc.log` / `vault.json` → matching identity sources; `firewall.log` / `pfsense` / `filterlog` / `openvpn` / `named.log` / `dhcpd` / `squid` / `nfdump` / `haproxy` / `ise.log` / `hostapd` / `bgpd` / `cisco` → matching network sources; `cloudtrail.json` / `vpcflow.txt` / `alb.log` / `rds.txt` / `azure_ad.json` / `gcp_audit.json` → matching cloud sources; `docker.log` / `k8s_audit.json` / `kubelet.log` / `pod.log` / `istio.log` / `helm.txt` / `registry.json` → matching container sources; `postgres.log` / `postgresql.log` / `mysql.log` / `mariadb.log` / `slow.log` / `mssql.txt` / `errorlog` / `oracle.txt` / `alert.log` / `mongod.log` / `mongodb.json` / `cassandra.txt` / `cassandra.log` / `redis.log` → matching `db_*`; `firewall.txt` stays `windows_firewall`; `system.log` without EventID → `linux_syslog`; `error.log` stays `web_error`; `access.log` stays `web_access`; `security.evtx.txt` / `powershell` / `defender` / `rdp` / `windows_firewall` → matching `windows_*`). Mixed files are classified **per line**. Masked usernames like `*****` map to `src_ip` as the entity. Then:

```bash
python -m src.pipeline normalize --config config/pipeline.yaml   # no-op when disabled
python -m src.pipeline ingest --config config/pipeline.yaml
```

**Policies (Phase 2 / 12 / 19):**

- **`enabled_sources`:** `ingestion.enabled_sources` is an allowlist of `log_source` names. Empty (default) means every registered family. Unknown names are a config error. Disabled families are still detected by loaders but fail extraction (`source disabled: …`) and are skipped at parse.
- **Dedup (Policy A):** `content_hash = sha256(raw_line)` encoded UTF-8 with `errors="replace"`; identical lines are dropped within a single run. The in-memory set is capped at `ingestion.dedup_memory_max_hashes` (default **2000000**); overflow auto-spills to a temporary SQLite file (`ingestion.dedup_backend: memory` \| `sqlite`). Hashes are not kept across runs. This is **dedup**, not evidence: replacement can hide original bytes.
- **File hashes (R4):** each ingest run writes `ingest_source_files` (`source_path`, `sha256` of **raw bytes**, `size_bytes`, `mtime_utc`, `run_id`). Staging Parquet parts are hashed and a Merkle of those hashes is stored on the ingest `pipeline_runs.params_json.staging`. Every stage’s `params_json.manifest` records git HEAD (if available), SHA-256 of `pipeline.yaml` and `drain3.ini`, numpy/scipy/sklearn/drain3 versions, and (R5) `parser_snapshot_id` / `model_snapshot_id` / `onnx_model_hash` / `cluster_run_id` when that stage produces them.
- **`ingest_row_id` (R5):** UUID5 of the source file’s SHA-256 + line number (stable across re-ingests of the same bytes). Not a random UUID.
- **Evidence line hash (opt-in):** `ingestion.evidence_line_hash: true` adds `evidence_hash = sha256(line_bytes)` on staging rows. Dedup still uses Policy A. Default **false**.
- **Dead-letter (R6):** `ingestion.max_line_bytes` (default **1048576**). Oversized lines and unreadable files go to `{parsed_dir}/ingest_dead_letter/dead-letter.jsonl`; ingest continues. Summary fields: `lines_dead_lettered`, `files_dead_lettered`.
- **Syslog year:** `ingestion.syslog_year_policy` (default **`carry`**) starts from the source file mtime year and increments on a Dec→Jan wrap while walking each file. `file_mtime` keeps the v1 single-year stamp. Naive timestamps are treated as UTC.
- **SSH fields:** syslog host token before `sshd[` is stored as `raw_fields.hostname` (enables `same_host` correlation). Session/disconnect/PAM/break-in lines extract entities in addition to the v1 fail/accept/invalid-user patterns. Masked usernames like `*****` still map to `src_ip`. If no user and no IP, the hostname is the entity (`entity_type=host`).
- **Encoding:** try UTF-8; on failure reopen as latin-1 with replacement.
- **Hive partitions:** `entity_id` folder names are percent-encoded (Windows-safe for `*` etc.); original ids stay in Parquet/DuckDB columns.
- **Re-run:** each ingest clears and rewrites `data/parsed/ingest_staging/`.

## Parse

Requires a prior successful `ingest` (staging Parquet must exist):

```bash
python -m src.pipeline parse --config config/pipeline.yaml
```

**Policies (Phase 3 / R5):**

- **Input:** `data/parsed/ingest_staging/` only (does not re-read `data/raw/`). Staging is read in `source_path`, `line_number` order so Drain3 assignment is deterministic.
- **Skip:** rows missing `entity_id` or `event_timestamp` are skipped and counted.
- **Re-run:** full refresh of `data/parsed/events/` only; staging is left untouched. `templates` is rebuilt from the current run (no double-counted `occurrence_count`). Stale `incidents` / `correlation_edges` / `anomaly_events` are cleared first so DuckDB FKs do not block the wipe.
- **Drain3 snapshots:** live state remains `{baseline_dir}/drain3_state.bin`. Frozen copies live under `{baseline_dir}/snapshots/parse/<snapshot_id>/drain3_state.bin`. `parse.mode` is `train_and_snapshot` (default: train, then copy live to a content-addressed snapshot) or `reuse_snapshot` (copy the named freeze over live **before** mining; does not overwrite the freeze). `parse.start_empty: true` is a **named** empty miner (`snapshot_id` `empty`); do not rely on a leftover `drain3_state.bin` disappearing by accident. `parse.snapshot_id` is required for `reuse_snapshot` (use `empty` to start from a named empty miner).
- **`event_id`:** signed BIGINT derived from UUID5 of `parser_snapshot_id | content_hash | line_number | source_path` (same staging + same starting snapshot → same id). Not a 1..N counter.
- **`parser_snapshot_id`:** stored on `parsed_events` and on the parse run manifest (starting identity used for `event_id`). After `train_and_snapshot`, `parser_trained_snapshot_id` on the manifest is the hash to put in `parse.snapshot_id` for a later freeze.
- **DuckDB:** `templates` and `parsed_events` stay native tables (FK-safe). Date-partitioned Parquet under `data/parsed/events/` is the durable store; `parsed_events_parquet` is registered as a hive view for inspection.

## Bucket

Requires a prior successful `parse` (`parsed_events` must be populated):

```bash
python -m src.pipeline bucket --config config/pipeline.yaml
```

**Policies (Phase 4):**

- **Input:** native `parsed_events` table only (does not re-read staging or raw logs).
- **Output:** dense zero-filled per-entity count series under `data/timeseries/entity_id=<id>/`, synced to `entity_bucket_counts`. `entity_bucket_counts_parquet` is a hive view for inspection.
- **Grid:** half-open bins `[bucket_start, bucket_start + bucket_seconds)`; `bucket_start = floor(ts / W) * W` in UTC epoch seconds.
- **Zero-fill:** every bin from the entity's first to last event is emitted (including `event_count = 0`).
- **Re-run:** full refresh of `data/timeseries/` and `entity_bucket_counts`.
- **Config:** `bucketing.bucket_seconds` (default **600**) controls bin width only via YAML — do not hardcode elsewhere.

**Spectral coupling (SDD §7.5.5):** changing `bucket_seconds` without revisiting `spectral.window_hours` and `spectral.baseline_max_nperseg` breaks Phase 6 resolution assumptions. Keep defaults aligned unless you retune spectral config deliberately.

## Detect statistical

Requires a prior successful `bucket` (`entity_bucket_counts` must be populated):

```bash
python -m src.pipeline detect-statistical --config config/pipeline.yaml
```

**Policies (Phase 5):**

- **Input:** native `entity_bucket_counts` table only.
- **Output:** sliding-window rate scores under `data/scores/statistical/entity_id=<id>/`, synced to `statistical_window_scores`. `statistical_window_scores_parquet` is a hive view for inspection.
- **Window:** `statistical.window_buckets` (default **6**) × `bucketing.bucket_seconds` (default **600**) = 1-hour sliding windows, stepped 1 bucket at a time.
- **Scoring:** robust median/MAD z-score (SDD §7.5.4) over each entity's window sums.
- **Flagging:** one-sided — `flagged = rate_z >= statistical.z_threshold` (default **4.0**); low-rate / stealth volume-drop is spectral/ML’s job, not statistical. **4.0 is a heuristic**, not a p-value — see [`../KNOWN_LIMITATIONS.md`](../KNOWN_LIMITATIONS.md).
- **Cold start:** entities with fewer than 24 windows are skipped.
- **Re-run:** full refresh of `data/scores/statistical/` and `statistical_window_scores`.
- **Honesty:** anomaly `metadata` records `rule: "rate_z >= z_threshold"` so analysts can see the one-sided rate role.

## Detect changepoint

Requires a prior successful `bucket` (`entity_bucket_counts` must be populated). Does **not** replace `detect-spectral`.

```bash
python -m src.pipeline detect-changepoint --config config/pipeline.yaml
```

**Policies (Phase 52):**

- **Input:** native `entity_bucket_counts` only. Missing this table is a hard error; correlate still skips the source if there are no flagged windows.
- **Output:** CUSUM scores under `data/scores/changepoint/entity_id=<id>/`, synced to `changepoint_window_scores`. `changepoint_window_scores_parquet` is a hive view for inspection.
- **Algorithm:** two-sided tabular CUSUM. Median / MAD-sigma from the first `changepoint.baseline_buckets` (default **48**, ~8 h at 600 s). Allowance `drift_k` (default **0.5** σ) and decision `decision_h` (default **5.0** σ). Consecutive flagged buckets collapse into one window. `direction` is `up` or `down`.
- **Flagging:** `flagged` when `max(S+, S−) / σ ≥ decision_h` after the baseline warm-up. Catches persistent mean jumps **and** stealth volume drops (statistical is high-rate only).
- **Cold start:** entities with fewer than `min_history_buckets` (**48**) are skipped (no scores).
- **Re-run:** full refresh of `data/scores/changepoint/` and `changepoint_window_scores`.
- **`run-all`:** runs after `detect-ml` and before `correlate`. Not required for correlate.

## Detect seasonal

Requires a prior successful `bucket`. Does **not** replace spectral or changepoint.

```bash
python -m src.pipeline detect-seasonal --config config/pipeline.yaml
```

**Policies (Phase 61):**

- **Input:** native `entity_bucket_counts`. Missing table → hard error; correlate skips the source when no flags.
- **Output:** residual scores under `data/scores/seasonal/entity_id=<id>/`, synced to `seasonal_window_scores`.
- **Algorithm:** median seasonal profile over `seasonal.period_buckets` (default **144** ≈ 24 h at 600 s); residual = count − seasonal; robust z on residuals. Consecutive flags merge. `direction` is `high` or `low`.
- **Flagging:** `|residual_z| ≥ seasonal.z_threshold` (default **4.0**). Set `seasonal.enabled: false` to no-op the stage.
- **Cold start:** need ≥ `max(min_history_buckets, 2×period_buckets)` (defaults **288** / **144**).
- **`run-all`:** runs after `detect-changepoint` and before `correlate`. Optional for correlate.

## Detect spectral

Requires a prior successful `bucket` (`entity_bucket_counts` must be populated):

```bash
python -m src.pipeline detect-spectral --config config/pipeline.yaml
```

**Policies (Phase 6):**

- **Input:** native `entity_bucket_counts` table only (independent of Phase 5/7).
- **Output:** Welch baselines in `spectral_baselines`, compact fingerprints in `entity_spectral_features`, and sliding-window scores under `data/scores/spectral/entity_id=<id>/`, synced to `spectral_window_scores`. `spectral_window_scores_parquet` is a hive view for inspection.
- **Sampling:** `fs = 1.0` (one sample per bucket); convert frequencies to hours via `period_hours = (1 / f) * bucket_seconds / 3600`.
- **FFT taper:** `spectral.window` (default **hann**; also `hamming`, `boxcar`, `blackman`, `bartlett`). Hann is the leakage-friendly default; boxcar is leakier. `spectral.min_welch_length` (default **4**) is the shortest series that will be scored.
- **Window duration:** `spectral.window_hours` (default **72**) × `bucketing.bucket_seconds` (default **600**) = **432** buckets per STFT window; step = `round(window_buckets * step_fraction)` (default **~144** buckets).
- **Scoring:** STFT total power → `energy_z`; Welch shape on each window segment vs rematched baseline PSD → Jensen-Shannon → `shape_js_z`. Both use robust median/MAD z-scores (SDD §7.5.4).
- **Flagging:** default `flagged = energy_z >= τ OR shape_js_z >= τ` with τ = `spectral.z_threshold` (**4.0**). Phase 51 adds optional `energy_z_threshold` / `shape_js_z_threshold`, `flag_mode` (`or` \| `and` \| `energy_only` \| `shape_only`), and `discount_last_window`. Dual OR inflates false positives; see [`../KNOWN_LIMITATIONS.md`](../KNOWN_LIMITATIONS.md).
- **Cold start:** skip window scoring when history is shorter than `window_buckets`; still write a Welch baseline when one can be computed. Too-short entities are **not** written to `entity_spectral_features` (they are unknown, not clustered as peer outliers).
- **STFT cap (R6):** `spectral.max_buckets_per_entity` (default **100000**) skips an entity instead of running an unbounded STFT. Counted as `entities_skipped_cap`, not a stage failure.
- **Re-run:** full refresh of spectral Parquet outputs and native spectral tables.

**Spectral coupling (SDD §7.5.5):** `window_hours` must span several cycles of the dominant period you expect to detect. Changing `bucket_seconds` without revisiting `spectral.window_hours` and `spectral.baseline_max_nperseg` breaks resolution assumptions. `detect-spectral` **hard-fails** if stored `entity_bucket_counts.bucket_seconds` does not match `bucketing.bucket_seconds`.

## Cluster

Requires a prior successful `detect-spectral` (`entity_spectral_features` must be populated):

```bash
python -m src.pipeline cluster --config config/pipeline.yaml
```

**Policies (Phase 6 / 14):**

- **Input:** native `entity_spectral_features` only.
- **Empty / small-N soft-skip:** if no features, or `COUNT(*) < spectral.cluster_min_entities` (default **20**), prints `nothing to cluster` (including `only N entities (min M)`) and exits 0 (`run-all` soft-skips). Does not write an all-`-1` cluster run.
- **Output:** `entity_clusters` with a `cluster_run_id` that is UUID5 of the sorted feature fingerprint plus `cluster_eps` / `cluster_min_samples` / `cluster_min_entities` (not a random UUID). Same features + same knobs → same id. Full refresh of the table. The id is stored on the cluster run manifest.
- **Algorithm:** `StandardScaler` + `DBSCAN(eps=cluster_eps, min_samples=cluster_min_samples)` over `[dominant_period_hours, dominant_power_frac, spectral_entropy, total_power]`.
- **Outliers:** `cluster_id == -1` (Phase 8 `cluster_outlier` source). Correlate skips outliers with no `spectral_baselines` row (cold start).
- **Re-run:** full refresh of `entity_clusters` for the new run id.

## Detect ML

Requires a prior successful `parse` (`parsed_events` must be populated):

```bash
python -m src.pipeline detect-ml --config config/pipeline.yaml
```

**Policies (Phase 7 / 14 / R5):**

- **Input:** native `parsed_events` table only (independent of statistical/spectral).
- **Output:** sequence anomaly scores under `data/scores/ml/entity_id=<id>/`, synced to `ml_window_scores`. `ml_window_scores_parquet` is a hive view for inspection.
- **Window:** non-overlapping duration `statistical.window_buckets * bucketing.bucket_seconds` (default **3600s**), aligned to the bucket grid; windows with fewer than 5 events are skipped.
- **Features:** top-20 template counts, top-50 bigram counts, sequence length, unique template count, Shannon entropy. Vocab is frozen with the model snapshot (not silently rebuilt on `reuse_snapshot`).
- **Model:** `ml.model_type` is `isolation_forest` (default), `autoencoder`, or `onnx`. IsolationForest and autoencoder use `ml.mode` `refit_and_snapshot` (pickle under `{baseline_dir}/snapshots/ml/<sha256>/isolation_forest.pkl` or `autoencoder.pkl`) or `reuse_snapshot` (`ml.snapshot_id` required). Autoencoder = sklearn MLP reconstruction MSE on the same feature vectors (`ae_hidden_dims`, `ae_max_iter`). ONNX loads `ml.onnx_model_path` plus sibling `{stem}.vocab.json` via onnxruntime (CPU); missing/corrupt model hard-fails with **no** IsolationForest fall-through. Manifest records `onnx_model_hash` when the file exists. Export: `python scripts/export_ml_onnx.py --baseline-dir data/baselines --snapshot-id <id> --model-type autoencoder --output data/models/ae.onnx` (optional `skl2onnx`). Compare IF vs AE on labels: `python scripts/compare_ml_models.py --config config/pipeline.yaml` (writes `ml_model_compare.json` / `.md` under `data/reports/eval/`; pass `--labels` to override `evaluation.labels_path`). Per-entity models are **Not in v6**.
- **Flagging:** default `ml.flagging: mad_threshold` — one-sided `robust_z(model_score) >= ml.mad_k` (default **4.0**). This does **not** force ~2% flags. Opt in to v1 with `flagging: predict` (uses `ml.contamination`, default **0.02**; AE/ONNX map predict → MAD). Also `score_threshold` (requires `ml.score_threshold`) and `none` (scores only). Same 4.0 heuristic as the other detectors — [`../KNOWN_LIMITATIONS.md`](../KNOWN_LIMITATIONS.md).
- **Attribution:** flagged ML windows store coarse `attribution_json` (top contributing features / templates). Correlate + explainability expose them on the why-flagged card. Not SHAP.
- **Cold start:** if `ml.mode` is `refit_and_snapshot` and fewer than `ml.min_windows_to_fit` (default **20**) windows exist, skip the fit and write 0 rows (IF/AE). `reuse_snapshot` / `onnx` still scores a smaller window set. ONNX misconfiguration fails before the cold-start skip.
- **Scores:** higher `model_score` = more anomalous. Rows store `model_snapshot_id` and optional `attribution_json`.
- **Re-run:** full refresh of `data/scores/ml/` and `ml_window_scores`.

## Correlate

Requires at least one flagged detector source (statistical / spectral / ML / changepoint) or cluster outliers:

```bash
python -m src.pipeline correlate --config config/pipeline.yaml
```

**Policies (Phase 8 / 11 / 14 / 54):**

- **Partial inputs:** never requires every detector. Missing sources are logged and skipped; zero sources → hard error on direct CLI (`NothingToCorrelate`; soft-skip in `run-all`). Invalid `correlation.*` values are a hard `CorrelationError` (direct CLI exit 1; `run-all` lists correlate as **failed**).
- **Output:** native DuckDB tables `anomaly_events`, `correlation_edges`, `incidents` (full wipe/replace each run).
- **Merge:** flagged windows → common schema; `source_detector` ∈ `statistical` \| `spectral` \| `ml` \| `cluster_outlier` \| `changepoint`. Cluster-outlier windows use `correlation.cluster_outlier_window` (default **`overlapping_flags`**, not entity lifetime). Lookback fallback: `cluster_outlier_lookback_days` (default **14**). Opt in to v1 lifetime with `entity_lifetime`. Cluster outliers without a `spectral_baselines` row are skipped.
- **Promotion (Phase 54):** `correlation.promotion.mode` defaults to **`any_flag`** (pre-54 behaviour). `severity_boost` raises `high`/`critical` only when distinct detectors ≥ `promotion.min_detectors` (default **2**). `min_detectors` mode still writes all `anomaly_events` but **drops** incidents below that agreement (can hide single-detector truth). The UI/API list filter `min_detectors` is independent of this emit policy. See [`../KNOWN_LIMITATIONS.md`](../KNOWN_LIMITATIONS.md) §3.1.
- **Metadata:** statistical `{rate_z, rule: "rate_z >= z_threshold"}`; spectral `{energy_z?, shape_js_z?, rule: "energy_or_shape"}`; ml `{model_type, flagging, model_score}`; cluster_outlier `{cluster_run_id, window_policy}`.
- **Sessions:** per-entity gap `correlation.session_gap_minutes` (default **30**); IP/host linking prefers edges (`same_ip` / `same_host`) over aggressive session merges. `same_ip` / `same_host` edges are only created for events inside `correlation.ip_link_horizon_hours` (default **24**) of the anomaly window.
- **Incidents:** same-entity flags farther apart than `correlation.incident_gap_minutes` (default **360**) become separate incidents. A session that spans that gap does **not** merge the two chains. `incident_id` is UUID5 of primary entity + min/max window + SHA-256 of the sorted anomaly-id set (stable across re-runs of the same set). After changing this recipe, re-run `correlate` then `report`.
- **Severity:** `low` / `medium` / `high` / `critical` from detector agreement + span (agreement threshold fixed at **2** under `any_flag`; configurable under `severity_boost` / `min_detectors` modes). `summary_text` is a readable sentence (entity kind, anomaly count, detector roles, span, IP/host linkage, top score).
- **Degraded mode:** if `parsed_events` are missing for anomalous entities, anomalies/incidents still write; edges/sessions are skipped with a warning.

## Report

Requires `incidents` rows (from a prior `correlate`):

```bash
python -m src.pipeline report --config config/pipeline.yaml
```

**Policies (Phase 9 / 17):**

- **Input:** warehouse only (`incidents`, linked `anomaly_events`, optional timeline via `correlation_edges` → `parsed_events`).
- **Output:** `data/reports/incident_<incident_id>.md` **and** `incident_<incident_id>.html` — **overwrite** on each re-run (batch refresh). HTML is self-contained (inline CSS, no Chart.js) so it opens from disk.
- **Template:** Jinja2 at `reporting.template_path` and optional `reporting.html_template_path` (entity, time range, summary, detector agreement, activity/PSD SVG in HTML, top-N anomalies by detector, edge counts, timeline, high-rate footnote). Re-run `report` after correlate so files match the v5 templates.
- **LLM:** `reporting.use_llm_narrative` defaults to **false** (no network). When `true`, calls local Ollama (`reporting.llm_model`) with `temperature: 0` and `seed: 42`; on failure logs a warning and still writes the deterministic files. On success, adds an LLM narrative section and updates `incidents.summary_text`.
- **Empty:** if no incidents, prints `nothing to report` and exits 0 (`run-all` soft-skips).
- **Dashboard:** Next.js lists reports at `/reports` and views them at `/reports/[filename]`. `GET /api/v1/reports/{filename}` serves files **inline** (names must match `incident_*.md|html`).

Enable Ollama later: pull a local model, set `use_llm_narrative: true` and `llm_model` in `config/pipeline.yaml`, ensure Ollama listens on `127.0.0.1:11434`.

### Copilot provider (Phase 95)

Assistive Q/A only — **not** a detector. Adapter: `src/copilot/provider.py` + `src/copilot/settings.py`.

1. Copy [`.env.example`](./.env.example) → `code/.env` (gitignored).
2. Set `COPILOT_ENABLED=true` and choose `COPILOT_PROVIDER` (`ollama`, `openai_compat`, or `gemini`).
3. Also set `copilot.enabled: true` in `config/pipeline.yaml` (**dual-gate** — both required for **chat**).
4. Cloud keys: `OPENAI_API_KEY` / `OPENAI_BASE_URL` or `GEMINI_API_KEY` in `.env` only — never `NEXT_PUBLIC_*`, never committed YAML.
5. Ollama default: `OLLAMA_BASE_URL=http://127.0.0.1:11434`, `COPILOT_MODEL=qwen2.5:14b`.
6. Gemini: set `COPILOT_PROVIDER=gemini`, `GEMINI_API_KEY=…`, and leave `COPILOT_MODEL=auto` (or empty) so the adapter lists models and picks a suitable `generateContent` Flash model. Pin a name (e.g. `gemini-2.0-flash`) to override.

### Copilot orchestration (code map)

In-app architecture (modules, mermaid graphs, tools): **`/docs/reference/copilot-architecture`**.

| Module | Role |
|---|---|
| `src/api/routes/v1/copilot.py` | `GET …/copilot/status`, `POST …/copilot/chat` |
| `src/copilot/pocketflow.py` | Vendored Pocket Flow core |
| `src/copilot/flow.py` | Chat: `PackContext` → `Decide` ⇄ tool nodes → `Answer` |
| `src/copilot/tools.py` | Allow-listed read-only tools |
| `src/copilot/provider.py` + `settings.py` | LLM wrapper + dual-gate |
| `src/copilot/insight_flow.py` | Insight: `LoadBrief` → `Summarize` → `WriteFile` |
| `src/reporting/persist.py` | Opt-in Insight at report stage (soft-skip) |

Chat turn (one HTTP request, non-stream):

```text
POST /api/v1/copilot/chat
  → dual-gate + build_provider
  → run_chat_turn(shared)
       PackContext → Decide ⇄ {incident, why, report, docs, rank, …} → Answer
  → { reply, citations, tools_used, provider, model }
```

`Decide` is hybrid: rules first, optional LLM explore/answer, max **5** tool loops. Pocket Flow does **not** wrap detectors / `STAGE_ORDER`.

### Copilot chat API (Phase 96) + floating UI (Phase 97)

`POST /api/v1/copilot/chat` runs the Pocket Flow turn above with allow-listed tools (`get_incident_brief`, `get_why_flagged`, `get_report_excerpt`, `get_docs_section`, `rank_entities_by_anomalies`, `list_incidents_ranked`, `get_entity_overview`). Disabled / provider down → **HTTP 503**. SSE streaming is deferred.

`GET /api/v1/copilot/status` → `{ enabled, provider, model, reason }` (no secrets).

Next.js: floating fab + panel (`web/components/copilot/`). **Add to chat** via page buttons, report/Docs controls, and **text selection** prompt (`PromptSelectionAddToChat`). Attachments are capped client-side (`MAX_ATTACHMENT_CHARS`).

### AI Insight report (Phase 98)

Opt-in summary beside Jinja reports (does **not** replace them; does not change severity/scores).

1. Set `copilot.ai_insight.enabled: true` in `pipeline.yaml`.
2. Ensure provider settings in `code/.env` (same adapter as chat). Chat dual-gate is **not** required for Insight.
3. Run `python -m src.pipeline report` → writes `data/reports/incident_<id>_ai_insight.md` when the LLM succeeds.
4. Soft-fail: LLM down → warning + skip Insight; deterministic `.md`/`.html` still written.
5. `pipeline_runs` params record `ai_insight_enabled` / attempted / successes / skipped.

Sits **alongside** `reporting.use_llm_narrative` (legacy Ollama-only narrative inside Jinja). Prefer the Phase 95 provider for new work.

```bash
python -m pytest tests/test_copilot_provider.py tests/test_copilot_chat.py tests/test_ai_insight.py -q
```

Honesty catalogue: [`KNOWN_LIMITATIONS.md`](../KNOWN_LIMITATIONS.md) §4.7. In-app Docs: `/docs/getting-started/copilot` (how-to), `/docs/reference/copilot-architecture` (code-level orchestration).

## Evaluate (Phase 15)

Score already-written detector flags and incidents against a labels file. This does **not** re-run detection and is **not** part of `run-all`.

```bash
python -m src.pipeline evaluate --config config/pipeline.yaml
python -m src.pipeline evaluate --config config/pipeline.yaml --cold-start-synthetic
```

Requires `evaluation.labels_path` in `config/pipeline.yaml` (CSV or Parquet). Missing or unreadable labels → exit 1. Precision of 0 is a valid result (exit 0).

**Labels schema** (`entity_id` and `label` required):

```text
entity_id,window_start,window_end,label,attack_type
alice,2024-01-01T10:00:00Z,2024-01-01T11:00:00Z,attacker,bruteforce
bob,,,benign,
```

`label` is `benign` or `attacker`. Both timestamps empty → entity-level label (any flag on that entity counts). ISO-8601 UTC. **Unlabeled entities are ignored** — they are not counted as benign. Only explicit `benign` rows are precision negatives.

**Overlap:** `evaluation.overlap_rule` is `any` (default: any shared time) or `iou_0_1` (intersection-over-union ≥ 0.1). Entity-level labels (empty windows) still match any detection on that entity. Missing detector tables (never written) are omitted from the JSON, not zero-filled.

**Outputs:** `evaluation.output_dir` (default `data/reports/eval/`) → `metrics.json` and `metrics.md`. When `write_entity_labels: true`, matching `entities.label` rows are updated (attacker wins if both). `--cold-start-synthetic` appends a 1d/3d/7d/14d spectral history table from an in-memory rhythm series (not your SSH warehouse).

### Threshold calibration (Phase 50)

Sweep cutoffs on **stored** window scores (does not re-run detectors; does not change YAML):

```bash
python scripts/calibrate_thresholds.py --config config/pipeline.yaml
python scripts/calibrate_thresholds.py --config config/pipeline.yaml \
  --labels tests/fixtures/labels/demo_eval.csv
```

Uses `evaluation.labels_path` when set; otherwise defaults to `tests/fixtures/labels/demo_eval.csv`. Writes `calibration.json` + `calibration.md` under `evaluation.output_dir`. τ grid default: `3.0, 3.5, 4.0, 4.5, 5.0` for `statistical.z_threshold`, `spectral.z_threshold` (dual OR), and `ml.mad_k`. See the Decision section in `calibration.md` and [`KNOWN_LIMITATIONS.md`](../KNOWN_LIMITATIONS.md) §1.

### Optional LANL / CERT labels

Do **not** commit LANL or CERT datasets. Point `evaluation.labels_path` at a local file you prepare:

1. Obtain [LANL Unified Host and Network Dataset](https://csr.lanl.gov/data/2017/) (authentication) or the [CERT insider-threat dataset](https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247) under their licenses.
2. Map compromise / red-team intervals into the schema above (`entity_id`, `window_start`, `window_end`, `label=attacker` or `benign`). Leave unlabeled users out of the file (unlabeled ≠ benign).
3. Set `evaluation.labels_path` to that CSV/Parquet path, run detectors + correlate on the matching corpus, then `evaluate`.

This repo does not ship LANL/CERT numbers; synthetic and injected-label fixtures are the Phase 15 gate.

## CLI

```bash
python -m src.pipeline --help
python -m src.pipeline <subcommand> --config config/pipeline.yaml
```

| Subcommand | Status |
|---|---|
| `normalize` | Implemented (Phase 80–81) — opt-in archive expand + EVTX/journal adapters; success-skips when `normalize.enabled: false` |
| `ingest` | Implemented (Phase 2) |
| `parse` | Implemented (Phase 3) |
| `bucket` | Implemented (Phase 4) |
| `detect-statistical` | Implemented (Phase 5) |
| `detect-spectral` | Implemented (Phase 6) |
| `cluster` | Implemented (Phase 6) |
| `detect-ml` | Implemented (Phase 7) |
| `detect-changepoint` | Implemented (Phase 52) — CUSUM on bucket counts; optional for correlate |
| `detect-seasonal` | Implemented (Phase 61) — seasonal residual robust-z; optional for correlate |
| `correlate` | Implemented (Phase 8) |
| `report` | Implemented (Phase 9 / 17) |
| `evaluate` | Implemented (Phase 15) — scores existing detections against a labels file; **not** part of `run-all` |
| `shard-split` | Implemented (Phase 88) — line-safe split of one on-disk log → `sharding.output_dir/<run_id>/` + `manifest.jsonl`; **not** part of `run-all` (does not start ingest/detect) |
| `run-sharded` | Implemented (Phases 89–91) — `--through parse` stops after append ingest/parse; `--through report` (default) gates on all shards then runs **one** bucket→detectors→correlate→report. `corpus_digest` = Merkle of shard hashes. UI job `mode=run_sharded` when `sharding.enabled` |
| `run-all` | Runs full chain (`normalize` → `ingest` → … → `detect-ml` → `detect-changepoint` → `detect-seasonal` → `correlate` → `report`); soft-skips cluster (no features), correlate (no sources), and report (no incidents); invalid correlate config **fails**. `--require complete` (or YAML `orchestration.run_all_require_complete: true`) treats those skips as failure |
| Dashboard | Next.js in `../web/` (uvicorn JSON API; optional Jinja if `serve_legacy_html: true`) |

**`run-all` skip policy:** soft-skips (warning) for cluster-with-no-features, correlate-with-no-sources (`NothingToCorrelate`), and report-with-no-incidents. Other `CorrelationError` values (bad `correlation.*` config) fail correlate. Exit non-zero if an implemented stage fails, or if `--require complete` / `run_all_require_complete` and any stage was skipped.

**Orchestration (Phase 13):** `orchestration.n_workers` (default **8**) and `orchestration.parallel_backend` (`none` \| `threads` \| `processes` \| `dask`) are read by `detect-statistical`, `detect-spectral`, `detect-changepoint`, and `detect-seasonal`. Worker count is `min(n_workers, cpu_count, n_entities)`, never below 1. Default backend is **`threads` on Windows** (DuckDB + process pools are painful) and `processes` elsewhere; `dask` falls back if the import fails. Parent process is the only DuckDB writer. `n_workers_used` / `parallel_backend` appear in the stage summary and `pipeline_runs.params_json`.

**Writer lock (R6):** `get_connection` takes an exclusive sidecar lock `{db_path}.writer.lock`. A second pipeline process fails immediately with `WarehouseBusyError`. Nested connections in the **same** process are reentrant. The dashboard uses `get_read_only_connection` with the **same** DuckDB access mode (not `read_only=True`) so in-process Pipeline jobs and UI polls do not hit DuckDB’s “different configuration” error; callers must not write through that helper.

**Corrupt Parquet (R6):** hive readers skip unreadable shards, record `pipeline_errors`, and continue. `run_all_require_complete: true` (or `--require complete`) hard-fails the stage if any shard was skipped.

**Load test (manual):** from `code/`, `python scripts/load_test_spectral.py --baseline-buckets 4320 --scale 10`. Procedure: [`tests/load/README.md`](tests/load/README.md). Not a CI gate.

## Confirm the warehouse

```bash
python -c "from src.config import load_config; from src.db.connection import get_connection; c=get_connection(load_config('config/pipeline.yaml')); print(c.execute('SELECT COUNT(*) FROM incidents').fetchone()); print(c.execute('SELECT incident_id, severity, summary_text FROM incidents ORDER BY severity DESC LIMIT 10').fetchall())"
```

Or open with the DuckDB CLI: `duckdb data/warehouse.duckdb` then `.tables`.

For a notebook walkthrough (incidents table + one entity’s buckets), open `notebooks/exploratory_analysis.ipynb` with this `code/` directory as the working directory.

## Tests

```bash
pytest
```

From `../web/`: `npm run build`. There is **no GitHub Actions workflow** in this repo — run pytest and the Next build locally. Node is not required for pipeline `pytest`.

## Docs (repo root)

- [../KNOWN_LIMITATIONS.md](../KNOWN_LIMITATIONS.md) — operator limitations: **4.0 is a heuristic**, dual `energy_z OR shape_js_z`, failure catalogue (shift-work, aliasing, Drain3 drift, cold start). Per-flag `anomalies[].explanation` and report **Why flagged** are R7. Incident overview (verdict + playbook + UTC + near-miss `warn_band`) is R8. Day-to-day operator reading: in-app Docs at `http://127.0.0.1:3000/docs` ([version nine](../docsm/version_nine/overall_plans.md)).
- [../SHORTCOMINGS.md](../SHORTCOMINGS.md) — pre-launch gap review; [../REMEDIATION_PHASES.md](../REMEDIATION_PHASES.md) — R1–R9 plan (complete)
- [../IMPROVEMENT_PHASES.md](../IMPROVEMENT_PHASES.md) — v6 index (Phases 47–55); full plan in [`../docsm/version_six/`](../docsm/version_six/)
- [../docsm/README.md](../docsm/README.md) — documentation index
- [../docsm/coding_rules.md](../docsm/coding_rules.md)
- [../docsm/version_one/overall_plans.md](../docsm/version_one/overall_plans.md) — v1 phases 1–10 (frozen)
- [../docsm/version_two/overall_plans.md](../docsm/version_two/overall_plans.md) — v2 phases 11–18 (frozen)
- [../docsm/version_three/overall_plans.md](../docsm/version_three/overall_plans.md) — v3 phases 19–36 (frozen); `log_source` registry §6
- [../docsm/version_four/overall_plans.md](../docsm/version_four/overall_plans.md) — v4: Next.js in `../web/` + `/api/v1`
- [../docsm/version_five/overall_plans.md](../docsm/version_five/overall_plans.md) — v5: rich investigation UI (frozen)
- [../docsm/version_six/overall_plans.md](../docsm/version_six/overall_plans.md) — v6: interactive triage + additive detectors (planned)
- [../ground_truth_log_anomaly_sdd.md](../ground_truth_log_anomaly_sdd.md) — source of truth (read-only)
