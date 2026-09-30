# Worked Examples: Anomaly Detection (Maths Deep Dive)

This document walks **statistical**, **spectral**, and **ML** detectors from inputs through equations to a flag decision, using the same helpers as the pipeline (`robust_z`, Welch / STFT, IsolationForest / autoencoder).

Numbers are **toy teaching values**, not a live warehouse export. The formulas match [`code/src/detectors/robust_z.py`](../code/src/detectors/robust_z.py), [`code/src/detectors/spectral/windowed.py`](../code/src/detectors/spectral/windowed.py), and [`code/src/detectors/ml/`](../code/src/detectors/ml/).

---

## Shared helper: robust z / MAD

Almost every “score” you see later is turned into a **robust z** before flagging.

**Median Absolute Deviation**

$$
\mathrm{MAD}(\mathbf{x}) = \mathrm{median}\bigl(|x_i - \mathrm{median}(\mathbf{x})|\bigr)
$$

**Robust z** (code constant $0.6745$, $\varepsilon = 10^{-9}$)

$$
z_i = 0.6745 \cdot \frac{x_i - \mathrm{median}(\mathbf{x})}{\mathrm{MAD}(\mathbf{x}) + \varepsilon}
$$

| Symbol | Meaning |
|--------|---------|
| $x_i$ | One window’s raw feature (count rate, STFT energy, JS divergence, ML model score, …) |
| $\mathrm{median}(\mathbf{x})$ | Median over the batch / entity window set being scored together |
| $\mathrm{MAD}$ | Robust spread |
| $0.6745$ | Scales MAD toward a $\sigma$-like unit **if** noise were Gaussian (log counts are not) |
| $\tau$ | Lab cutoff, default **4.0** — **not** a calibrated $p$-value |

**Flag rule (one-sided high, default)**

$$
\mathrm{flagged}_i = \mathbf{1}\{ z_i \ge \tau \}
$$

Edge cases in code: if MAD $= 0$ and all values equal the median → every $z = 0$; if MAD collapses but outliers exist → fall back to std scaling.

---

## 1. Statistical detector (rate / volume)

**What it measures:** How loud the **bucket count** is vs this entity’s typical median rate.

**Pipeline path:** `parsed_events` → time buckets → count series $\mathbf{c}$ → robust $z$ on counts → flag if $z \ge 4.0$.

### Setup

- Entity $e = \texttt{user:alice}$
- Bucket width $\Delta t = 600\,\mathrm{s}$ (10 minutes)
- Threshold $\tau = 4.0$

### Step 1 — Logs → events → counts

Each kept line becomes a parsed event with UTC time + entity. Detection math starts **after** parse.

Seven successive buckets for $e$:

$$
\mathbf{c} = (2,\,3,\,2,\,4,\,3,\,2,\,25)
$$

The last bucket is a burst (many auth failures).

| Variable | Holds |
|----------|--------|
| $c_i$ | Number of events for $e$ in bucket $i$ |
| $c_7 = 25$ | Burst window we will score |

### Step 2 — Median and MAD on $\mathbf{c}$

Sorted: $(2,2,2,3,3,4,25)$.

$$
m = \mathrm{median}(\mathbf{c}) = 3
$$

$$
|\mathbf{c} - m| = (1,\,0,\,1,\,1,\,0,\,1,\,22)
$$

Sorted deviations: $(0,0,1,1,1,1,22)$.

$$
\mathrm{MAD} = 1
$$

### Step 3 — Robust $z$ for the burst

$$
z_{25} = 0.6745 \cdot \frac{25 - 3}{1 + 10^{-9}} \approx 0.6745 \times 22 \approx 14.84
$$

Quiet window $c = 4$:

$$
z_4 = 0.6745 \cdot \frac{4 - 3}{1} = 0.6745
$$

### Step 4 — Threshold

$$
\mathrm{flagged}(25) = \mathbf{1}\{14.84 \ge 4.0\} = 1 \quad\text{(FLAGGED)}
$$

$$
\mathrm{flagged}(4) = \mathbf{1}\{0.6745 \ge 4.0\} = 0 \quad\text{(not flagged)}
$$

**Output row (conceptual):** `source_detector = statistical`, `score ≈ 14.84`, `flagged = true` for the burst window.

---

## 2. Spectral detector (rhythm: energy + shape)

**What it measures:** Whether this entity’s **frequency content** (how power is distributed over periods) changed — not only whether volume spiked.

**Pipeline path (code):**

1. Slide STFT windows on the bucket count series.
2. **Energy** $E_w = \sum_f |Z_{xx}(f,w)|^2$ (total STFT column power).
3. **Shape:** Welch PSD on the window segment, normalize to a probability vector $\mathbf{p}$; compare to rematched full-series baseline $\mathbf{q}$ with **Jensen–Shannon** divergence.
4. $\mathrm{energy\_z} = \mathrm{robust\_z}(\mathbf{E})$, $\mathrm{shape\_js\_z} = \mathrm{robust\_z}(\mathbf{J})$.
5. Default flag: $\mathrm{energy\_z} \ge \tau$ **OR** $\mathrm{shape\_js\_z} \ge \tau$ ($\tau = 4.0$).

### 2.1 Energy leg — equations

STFT of count series $\mathbf{c}$ with window length $W$ buckets (lab default ≈ 6 buckets ≈ 1 h at 600 s):

$$
E_w = \sum_{k} \bigl|Z_{xx}[k,w]\bigr|^2
$$

Then

$$
\mathrm{energy\_z}_w = 0.6745 \cdot \frac{E_w - \mathrm{median}(\mathbf{E})}{\mathrm{MAD}(\mathbf{E}) + \varepsilon}
$$

### Worked energy example

Suppose five successive STFT windows produce energies:

$$
\mathbf{E} = (2.0,\,2.2,\,1.8,\,2.1,\,12.0)
$$

| Variable | Value |
|----------|-------|
| $E_1\ldots E_4$ | Quiet rhythm ≈ 2 |
| $E_5 = 12.0$ | Loud energy burst |

Sorted: $(1.8, 2.0, 2.1, 2.2, 12.0)$. Median $m_E = 2.1$.

$$
|\mathbf{E} - m_E| = (0.1,\,0.1,\,0.3,\,0.1,\,9.9)
$$

Sorted: $(0.1, 0.1, 0.1, 0.3, 9.9)$. $\mathrm{MAD}_E = 0.1$.

For $E_5 = 12$:

$$
\mathrm{energy\_z}_5 = 0.6745 \cdot \frac{12.0 - 2.1}{0.1 + 10^{-9}} = 0.6745 \cdot 99 \approx 66.78
$$

$$
\mathbf{1}\{66.78 \ge 4.0\} = 1 \quad\Rightarrow\quad \textbf{energy leg FLAGS}
$$

### 2.2 Shape leg — Welch PSD + Jensen–Shannon

**Normalize Welch PSD to a probability vector** (code: `psd / sum(psd)`):

$$
p_k = \frac{S_{xx}(f_k)}{\sum_j S_{xx}(f_j)}, \qquad \sum_k p_k = 1
$$

$\mathbf{p}$ = current window shape; $\mathbf{q}$ = rematched baseline shape (same $nperseg$).

**Jensen–Shannon divergence** (SciPy `jensenshannon`; base $e$, returns $\sqrt{\mathrm{JS}}$ in nats-scale form). Teaching form with mixture $M = \tfrac{1}{2}(P+Q)$:

$$
D_{\mathrm{KL}}(P \Vert M) = \sum_k p_k \ln\frac{p_k}{m_k}
$$

$$
\mathrm{JS}(P,Q) = \tfrac{1}{2} D_{\mathrm{KL}}(P\Vert M) + \tfrac{1}{2} D_{\mathrm{KL}}(Q\Vert M)
$$

$$
J = \sqrt{\mathrm{JS}(P,Q)} \in [0,1]
$$

($J = 0$ identical shapes; larger $J$ = more different schedule / harmonic mix.)

Then

$$
\mathrm{shape\_js\_z}_w = 0.6745 \cdot \frac{J_w - \mathrm{median}(\mathbf{J})}{\mathrm{MAD}(\mathbf{J}) + \varepsilon}
$$

### Worked shape example (3-bin toy PSDs)

Baseline $\mathbf{q}$ (daily rhythm concentrated at one bin):

$$
\mathbf{q} = (0.70,\,0.20,\,0.10)
$$

Normal window $\mathbf{p}_{\mathrm{ok}}$:

$$
\mathbf{p}_{\mathrm{ok}} = (0.68,\,0.22,\,0.10)
$$

Anomalous schedule shift $\mathbf{p}_{\mathrm{bad}}$ (power moved to another period):

$$
\mathbf{p}_{\mathrm{bad}} = (0.15,\,0.25,\,0.60)
$$

**Compute $J$ for $\mathbf{p}_{\mathrm{ok}}$ vs $\mathbf{q}$**

$$
M = \tfrac{1}{2}(\mathbf{p}_{\mathrm{ok}}+\mathbf{q}) = (0.69,\,0.21,\,0.10)
$$

$$
D_{\mathrm{KL}}(P_{\mathrm{ok}}\Vert M)
  \approx 0.68\ln\frac{0.68}{0.69} + 0.22\ln\frac{0.22}{0.21} + 0.10\ln\frac{0.10}{0.10}
$$

$$
D_{\mathrm{KL}}(P_{\mathrm{ok}}\Vert M)
  \approx 0.68(-0.0146) + 0.22(0.0465) + 0 \approx 0.0003
$$

$$
D_{\mathrm{KL}}(Q\Vert M)
  \approx 0.70\ln\frac{0.70}{0.69} + 0.20\ln\frac{0.20}{0.21} + 0.10\ln 1
$$

$$
D_{\mathrm{KL}}(Q\Vert M)
  \approx 0.70(0.0144) + 0.20(-0.0488) \approx 0.0003
$$

$$
\mathrm{JS}_{\mathrm{ok}} \approx 0.0003,\qquad J_{\mathrm{ok}} = \sqrt{0.0003} \approx 0.017
$$

**Compute $J$ for $\mathbf{p}_{\mathrm{bad}}$ vs $\mathbf{q}$**

$$
M' = \tfrac{1}{2}(\mathbf{p}_{\mathrm{bad}}+\mathbf{q}) = (0.425,\,0.225,\,0.350)
$$

$$
D_{\mathrm{KL}}(P_{\mathrm{bad}}\Vert M')
  \approx 0.15\ln\frac{0.15}{0.425} + 0.25\ln\frac{0.25}{0.225} + 0.60\ln\frac{0.60}{0.350}
$$

$$
D_{\mathrm{KL}}(P_{\mathrm{bad}}\Vert M')
  \approx 0.15(-1.041) + 0.25(0.105) + 0.60(0.539) \approx 0.190
$$

$$
D_{\mathrm{KL}}(Q\Vert M')
  \approx 0.70\ln\frac{0.70}{0.425} + 0.20\ln\frac{0.20}{0.225} + 0.10\ln\frac{0.10}{0.350}
$$

$$
D_{\mathrm{KL}}(Q\Vert M')
  \approx 0.70(0.499) + 0.20(-0.118) + 0.10(-1.253) \approx 0.201
$$

$$
\mathrm{JS}_{\mathrm{bad}} \approx 0.1955,\qquad J_{\mathrm{bad}} = \sqrt{0.1955} \approx 0.442
$$

**Robust $z$ across a batch of JS values**

Suppose five windows:

$$
\mathbf{J} = (0.02,\,0.01,\,0.03,\,0.02,\,0.442)
$$

Median $m_J = 0.02$. Absolute deviations: $(0,\,0.01,\,0.01,\,0,\,0.422)$.

Sorted: $(0, 0, 0.01, 0.01, 0.422)$. $\mathrm{MAD}_J = 0.01$.

$$
\mathrm{shape\_js\_z}_5 = 0.6745 \cdot \frac{0.442 - 0.02}{0.01} = 0.6745 \cdot 42.2 \approx 28.46
$$

$$
\mathbf{1}\{28.46 \ge 4.0\} = 1 \quad\Rightarrow\quad \textbf{shape leg FLAGS}
$$

### 2.3 Dual-OR decision (default `flag_mode: or`)

$$
\mathrm{flagged} = \mathbf{1}\{\mathrm{energy\_z} \ge \tau\} \;\lor\; \mathbf{1}\{\mathrm{shape\_js\_z} \ge \tau\}
$$

| Case | energy_z | shape_js_z | Result |
|------|----------|------------|--------|
| Volume burst, shape OK | 66.78 | 0.5 | **FLAG** (energy) |
| Schedule shift, volume OK | 0.8 | 28.46 | **FLAG** (shape) — Alice-class demo |
| Both quiet | 0.5 | 0.3 | not flagged |

Correlate often stores $\max(\mathrm{energy\_z}, \mathrm{shape\_js\_z})$ as the anomaly score for the spectral hit.

**Output row (conceptual):** `source_detector = spectral`, e.g. `energy_z ≈ 66.78` and/or `shape_js_z ≈ 28.46`, `flagged = true`.

---

## 3. ML detector (sequence: IsolationForest + autoencoder)

**What it measures:** Whether this window’s **template / bigram mix** is unusual vs the **current batch** vocab — independent of rate and rhythm by construction.

**Shared feature path (code):**

1. Slice template_id sequences into windows.
2. Global vocab: top **20** templates + top **50** bigrams + “other” bins + length, unique count, Shannon entropy → width $d \approx 75$.
3. $\mathbf{x}$ = count vector; StandardScaler → $\tilde{\mathbf{x}}$.
4. Model emits `model_score` (higher = more anomalous).
5. $\mathrm{mad\_z} = \mathrm{robust\_z}(\mathrm{model\_score})$; flag if $\mathrm{mad\_z} \ge \texttt{ml.mad\_k}$ (default **4.0**).

$$
d = 20 + 1 + 50 + 1 + 3 = 75
$$

Below we use a **4-D toy** vector so every number is hand-checkable. The algebra is identical to $d = 75$.

### 3.A Autoencoder (reconstruction MSE)

**Architecture (defaults):** MLP $d \to 32 \to 8 \to 32 \to d$ (ReLU hidden), trained with targets = inputs (`fit(X, X)`).

$$
\hat{\mathbf{x}} = f_\theta(\tilde{\mathbf{x}})
$$

$$
\mathbf{r} = \tilde{\mathbf{x}} - \hat{\mathbf{x}}
$$

$$
\mathrm{model\_score} = \frac{1}{d}\sum_{j=1}^{d} r_j^{2}
$$

Higher MSE ⇒ poorer reconstruction ⇒ more anomalous.

#### Worked AE example ($d = 4$)

Suppose after scaling, a **normal** window and a **weird** window:

$$
\tilde{\mathbf{x}}_{\mathrm{ok}} = (0.2,\,-0.1,\,0.0,\,0.1)
$$

$$
\hat{\mathbf{x}}_{\mathrm{ok}} = (0.18,\,-0.08,\,0.02,\,0.09)
$$

$$
\mathbf{r}_{\mathrm{ok}} = (0.02,\,-0.02,\,-0.02,\,0.01)
$$

$$
\mathrm{MSE}_{\mathrm{ok}} = \frac{0.02^{2}+(-0.02)^{2}+(-0.02)^{2}+0.01^{2}}{4} = \frac{0.0013}{4} = 0.000325
$$

Weird mix (rare template / odd bigrams) that the bottleneck cannot reconstruct:

$$
\tilde{\mathbf{x}}_{\mathrm{bad}} = (2.5,\,-1.8,\,3.0,\,-2.0)
$$

$$
\hat{\mathbf{x}}_{\mathrm{bad}} = (0.4,\,-0.3,\,0.5,\,-0.2)
$$

$$
\mathbf{r}_{\mathrm{bad}} = (2.1,\,-1.5,\,2.5,\,-1.8)
$$

$$
\mathrm{MSE}_{\mathrm{bad}} = \frac{2.1^{2}+(-1.5)^{2}+2.5^{2}+(-1.8)^{2}}{4} = \frac{16.15}{4} = 4.0375
$$

**MAD $z$ on a batch of MSE scores**

$$
\mathbf{s} = (0.0003,\,0.0004,\,0.0005,\,0.0002,\,4.0375)
$$

Median $m_s \approx 0.0004$. Absolute deviations ≈ $(0.0001, 0, 0.0001, 0.0002, 4.0371)$.

$\mathrm{MAD}_s \approx 0.0001$.

$$
\mathrm{mad\_z}_{\mathrm{bad}} = 0.6745 \cdot \frac{4.0375 - 0.0004}{0.0001} \approx 0.6745 \cdot 40371 \approx 27230
$$

(Extreme by construction in this toy — live scores are milder, but the **decision rule** is the same.)

$$
\mathbf{1}\{27230 \ge 4.0\} = 1 \quad\Rightarrow\quad \textbf{AE FLAGS}
$$

Attribution (not SHAP): rank $|r_j|$ — here features 3 and 1 dominate ($|2.5|$, $|2.1|$).

### 3.B IsolationForest (default model)

**Idea:** Random trees isolate points by random feature splits. Points that isolate in **few** splits are more anomalous.

sklearn `decision_function` is larger for **normal** points. The pipeline uses:

$$
\mathrm{model\_score} = -\texttt{decision\_function}(\tilde{\mathbf{x}})
$$

so **higher** `model_score` = more anomalous (same direction as AE MSE).

Path-length intuition (Liu et al.): expected path length $E(h(\mathbf{x}))$ short ⇒ anomaly. The continuous score is monotone with isolation difficulty.

#### Worked IF example (scores already from the forest)

Five windows’ `model_score` values (negated decision function):

$$
\mathbf{s}_{\mathrm{IF}} = (0.12,\,0.15,\,0.10,\,0.14,\,0.95)
$$

Median $m = 0.14$. Deviations: $(0.02, 0.01, 0.04, 0, 0.81)$.

Sorted: $(0, 0.01, 0.02, 0.04, 0.81)$. $\mathrm{MAD} = 0.02$.

$$
\mathrm{mad\_z}_5 = 0.6745 \cdot \frac{0.95 - 0.14}{0.02} = 0.6745 \cdot 40.5 \approx 27.32
$$

$$
\mathbf{1}\{27.32 \ge 4.0\} = 1 \quad\Rightarrow\quad \textbf{IsolationForest FLAGS}
$$

Quiet window $s = 0.15$:

$$
z = 0.6745 \cdot \frac{0.15 - 0.14}{0.02} = 0.6745 \cdot 0.5 \approx 0.34 < 4 \quad\Rightarrow\quad \text{not flagged}
$$

### 3.C Ensemble (optional IF + AE)

When enabled, each member produces its own MAD flag; fusion (default **majority**) decides. Ranking scores often take $\max$ of member `model_score` / `mad_z` for correlate continuity.

- **majority** (2 models): flag if at least 2 members flag
- **any**: flag if any member flags
- **unanimous**: flag only if every member flags

**Output row (conceptual):** `source_detector = ml` (or autoencoder / ensemble), `model_score`, `mad_z`, `flagged = true`.

---

## 4. How the three meet at correlate

| Detector | Raw feature(s) | Score into correlate | Typical story |
|----------|----------------|----------------------|---------------|
| Statistical | bucket count $c$ | robust $z(c)$ | volume burst |
| Spectral | $E_w$, $J_w$ | $\max(\mathrm{energy\_z}, \mathrm{shape\_js\_z})$ often | rhythm / schedule |
| ML | template vector $\mathbf{x}$ | robust $z(\mathrm{model\_score})$ | odd sequence mix |

Correlate **does not** average these into one magic number. It merges flagged windows into **incidents**, then assigns **severity** from detector **agreement** and promotion mode (`any_flag` / `severity_boost` / `min_detectors`).

Example narrative: statistical $z \approx 14.8$ **and** spectral shape $z \approx 28$ on the same entity window → stronger multi-detector incident than either alone.

---

## 5. What this demo is not

- Not a claim that live warehouses use these exact toy vectors.
- Not a Gaussian $p$-value derivation ($|z| \ge 4$ is a **lab convention**).
- Not SHAP / ATT&CK naming for ML attribution.
- Spectral 3-bin PSDs stand in for full Welch grids; IF path lengths are summarized by `decision_function` scores as in sklearn.

**Code sources of truth**

- Robust $z$: `code/src/detectors/robust_z.py`
- Spectral energy / JS: `code/src/detectors/spectral/windowed.py`
- IsolationForest / AE: `code/src/detectors/ml/isolation_forest.py`, `autoencoder.py`
- In-app Docs mirrors: `/docs/maths/robust-z`, `/docs/maths/spectral`, `/docs/maths/ml`, `/docs/maths/worked-example`
