<!-- SPDX-License-Identifier: Apache-2.0 -->
# ResonanceBFT — References

Each citation maps to a real, published paper with a verifiable link (arXiv / DOI /
publisher).  A focused verification pass on 2026-06-30 (web + arXiv + the authors' own
publication lists) confirmed each entry, corrected several ids/DOIs that an automated
deep-research survey had gotten wrong, and *removed* one wrong id outright — the corrections
are noted inline at each affected entry so the provenance is auditable.  Where a code
mechanism is only *inspired by* a result (not a verbatim implementation), the entry says so
explicitly.  Citations are short author-year tags in the code; the full entry is here.

## BFT / distributed agreement
- **Lamport, Shostak & Pease (1982)** — "The Byzantine Generals Problem," *ACM TOPLAS*.
  The `n ≥ 3f+1` / `quorum = n−f` foundation.
- **Cambus, Melnyk, Milentijević & Schmid (2025)** — "Approximate Agreement Algorithms
  for Byzantine Collaborative Learning," [arXiv:2504.01504](https://arxiv.org/abs/2504.01504).
  Approximate **Byzantine agreement** in collaborative learning (robust aggregation). We cite
  it for the *approximate-agreement* framing, NOT as a direct proof of our similarity-threshold
  lower bound — the `bft_safety_lower_bound` clamp `1 − 2f/(n−f)` is our own derivation, so the
  citation is context, not attribution. *(Verified 2026-06-30; the paper is about gradient
  aggregation in distributed ML, so we deliberately do not over-claim it as a threshold proof.)*
- **Douceur (2002)** — "The Sybil Attack," *1st Int'l Workshop on Peer-to-Peer Systems
  (IPTPS)*, pp. 251–260 — <https://www.microsoft.com/en-us/research/publication/the-sybil-attack/>.
  A single faulty entity presenting multiple identities can subvert redundancy. We implement
  the *within-round, single-identity* guard (`participate()` is idempotent per agent); minting
  *many* identities is the identity layer's problem, so we do not over-claim full Sybil
  resistance.
- **Alpos, Cachin, Tackmann & Zanolini (2019)** — "Asymmetric Distributed Trust,"
  [arXiv:1906.09314](https://arxiv.org/abs/1906.09314). Subjective/asymmetric Byzantine
  quorum systems — prior art for per-agent trust *topology* (which peers you include), as
  distinct from our per-agent trust *weighting* (magnitude); we cite it for the subjective-view
  idea, not for numerical weighting.
- **Sheng, Wang, Nayak, Kannan & Viswanath (2021)** — "BFT Protocol Forensics," ACM CCS 2021,
  [arXiv:2010.06785](https://arxiv.org/abs/2010.06785). Formalizes *forensic support*:
  identifying Byzantine culprits with irrefutable cryptographic evidence after a safety fault,
  with tight bounds on how many are attributable. *How we use it:* grounds the **equivocation
  conflict certificate** (`build_/verify_/collect_equivocation_certificate` in
  `validators/bft_validators.py`) — when an agent signs two distinct commitments for one
  `(round_id, aid)`, we bundle the conflicting *signed* records into a self-contained,
  third-party-verifiable proof. We deliberately implement only this clean, provable case (not
  full Polygraph-style O(n²) accountability), and note that identity↔pubkey binding is the
  identity layer's job. *(arXiv id verified 2026-06-30.)*
- **Yin, Chen, Ramchandran & Bartlett (2018)** — "Byzantine-Robust Distributed Learning:
  Towards Optimal Statistical Rates," ICML 2018, [arXiv:1803.01498](https://arxiv.org/abs/1803.01498) —
  <https://arxiv.org/abs/1803.01498>. *How we use it:* the commit centroid is a **coordinate-wise
  trimmed mean** (`_trimmed_centroid`) over the non-tampered sealed vectors — drop the **configured
  fault bound `f = ⌊(n−1)/3⌋`** of extreme values per axis per side — so a minority submitting *valid*
  (correctly sealed/signed, hence not flagged `tampered`) but biased belief values cannot drag the
  centroid. This raises the centroid's breakdown point from 0 (plain mean) toward the honest majority
  while staying deterministic (it sorts per-axis values, not agents → resolver-independent). Box
  validity needs `trim ≥ (Byzantine values present)`, and at most `f` of the `k` committed records can
  be Byzantine, so we MUST trim by `f` — trimming by `⌊(k−1)/3⌋` of the *arrived* records would
  under-trim at the `n−f` quorum floor (`n=7, f=2, k=5`: `⌊(k−1)/3⌋=1 < f=2`, leaving a biased extreme
  in the box). `_trimmed_mean` caps trim at `⌊(k−1)/2⌋` so ≥1 value always survives (at the floor
  `k=2f+1` this leaves the coordinate median — still box-valid). Regression:
  `test_box_validity_at_quorum_floor_trims_by_configured_f`. *(arXiv id verified 2026-06-30.)*

## Value-space consensus — multidimensional approximate Byzantine agreement (MBAA)

ResonanceBFT agrees over a **five-axis value/belief vector**, not a discrete bit. The rigorous
notion for consensus over continuous/vector values is **approximate** (not exact) agreement:
honest outputs are within ε of each other **and** inside the range of honest inputs (validity).
This section grounds ResonanceBFT's cross-view guarantee as **box-validity MBAA** (all citations
verified 2026-06-30).

- **Dolev, Lynch, Pinter, Stark & Weihl (1986)** — "Reaching Approximate Agreement in the
  Presence of Faults," *JACM* 33(3):499–516, doi:10.1145/5925.5931. Defines **ε-agreement**
  (honest outputs within ε) + **validity** (output in the range of honest inputs), solvable iff
  `n ≥ 3f+1` via iterated trimmed-mean averaging that contracts the diameter each round. *How we
  use it:* the canonical definition our cross-view guarantee instantiates; the trimmed-mean
  contraction is the scalar case of our commit + HK deliberation.
- **Vaidya & Garg (2013)** — "Byzantine Vector Consensus in Complete Graphs," PODC 2013,
  [arXiv:1302.2543](https://arxiv.org/abs/1302.2543) (VERIFIED). Tight bounds for `d`-dimensional agreement: exact needs
  `n ≥ max(3f+1,(d+1)f+1)`; **approximate (ε-agreement + convex validity) needs `n ≥ (d+2)f+1`**
  (so `n ≥ 7f+1` at d=5). *How we use it:* the fault-dimension law that makes **convex** validity
  expensive — the reason we deliberately keep **box** validity at `n ≥ 3f+1`.
- **Mendes, Herlihy, Vaidya & Garg (2015)** — "Multidimensional Agreement in Byzantine Systems,"
  *Distributed Computing* 28(6):423–441, doi:10.1007/s00446-014-0240-5. The **SafeArea**
  construction (intersection of convex hulls of (n−f)-subsets) that guarantees convex validity.
  *How we use it:* the convex-validity alternative we cite and consciously do **not** adopt (its
  cost: tighter fault bound + worse centroid approximation).
- **Cambus & Melnyk (2023/2025)** — "Centroid Approximation with Multidimensional Approximate
  Agreement Protocols," [arXiv:2306.12741](https://arxiv.org/abs/2306.12741) (VERIFIED); ScienceDirect 2026. Proves **convex
  validity** forces a ≥ `2d` worst-case centroid error while a **box-validity** (trusted-hyperbox)
  algorithm achieves `2√d` at the better `f < n/3` resilience, and that **coordinate-wise trimmed
  means give box validity, not convex validity** in d ≥ 2. *How we use it:* the direct
  justification that our coordinate-wise trimmed-mean commit (`_trimmed_mean` / `_box_validity`)
  provides **box validity** — the correct, precise claim (`2√5 ≈ 4.47`, `f < n/3`), and that
  choosing box over convex is *better* on both accuracy and resilience.
- **Vaidya (2012)** — "Matrix Representation of Iterative Approximate Byzantine Consensus in
  Directed Graphs," [arXiv:1203.1888](https://arxiv.org/abs/1203.1888). Iterative approximate Byzantine consensus (drop f extremes,
  average) = stochastic averaging, the same structure as DeGroot/Hegselmann–Krause opinion
  dynamics. *How we use it:* makes rigorous that our **HK deliberation IS the iterative-averaging
  convergence engine**, with the commit's trimmed mean as the Byzantine filter (deliberation need
  only converge; the committed aggregate carries the validity).
- **Chazelle & Wang (2013)** — "On the Convergence of the Hegselmann–Krause System," ITCS 2013.
  First polynomial-time convergence bound for HK in fixed dimension. *How we use it:* bounds the
  number of deliberation rounds to reach ε-agreement in the 5-axis space; the contraction is
  verified in `test_deliberation_contracts_opinion_diameter` (honest opinion diameter is
  monotonically non-increasing across deliberation steps and strictly converges).
- **Berdoz, Rugli & Wattenhofer (2026)** — "Can AI Agents Agree?," [arXiv:2603.01213](https://arxiv.org/abs/2603.01213) (VERIFIED).
  Evaluates LLM agents in a Byzantine consensus game and finds reliable agreement does *not*
  emerge — failures are dominated by **loss of liveness (timeouts, stalled convergence)**, not
  value corruption. *How we use it:* motivation — this is exactly the failure mode ResonanceBFT
  engineers against: the driver commits at the `n−f` quorum (never blocking on slow/silent
  agents) and the HK deliberation provides a bounded-round convergence engine, so liveness does
  not stall.

## Opinion dynamics / bounded confidence (deliberation, ε)
- **Hegselmann & Krause (2002)** — "Opinion Dynamics and Bounded Confidence," *JASSS* 5(3) —
  <https://www.jasss.org/5/3/2.html>. The HK model `deliberate()` implements.
- **Deffuant, Neau, Amblard & Weisbuch (2000)** — "Mixing beliefs among interacting agents,"
  *Advances in Complex Systems* 3:87–98. The companion bounded-confidence model.
- **Li, Luo & Porter (2024)** — "Bounded-Confidence Models of Opinion Dynamics with
  Adaptive Confidence Bounds," [arXiv:2303.07563](https://arxiv.org/abs/2303.07563).
  Adaptive per-node ε; our per-dyad ε is a variant of this.
- **Li, Luo & Chu (2025)** — "Bounded-Confidence Models of Multi-Dimensional Opinions with
  Topic-Weighted Discordance," [arXiv:2502.00284](https://arxiv.org/abs/2502.00284).
  Per-topic ε weighting → grounds the per-axis ε multipliers.
- **Thompsky, Wu, Porter & Luo (2026)** — "A Bounded-Confidence Model of Opinion Dynamics
  with Adaptive Interaction Probabilities," [arXiv:2605.20418](https://arxiv.org/abs/2605.20418) —
  <https://arxiv.org/abs/2605.20418>. Extends Deffuant–Weisbuch with **adaptive edge weights**
  that govern interaction probability and **increase after positive (co-commit-like)
  interactions** — pair-history-dependent receptivity. ResonanceBFT adapts the same
  pair-history signal into the ε *radius* (co-commit boost) rather than the interaction
  probability. *(Verified 2026-06-30 against arXiv and M. A. Porter's UCLA publication list. A
  2026-06-30 deep-research pass that flagged a conflicting id `2506.00362` was itself wrong —
  that id is an unrelated paper, "FSNet" by Nguyen & Donti; `2605.20418` is the correct one.)*

## Layer-3 axis-weight learning + smooth saturating emphasis (`_axis_step_multiplier`)
The learned per-axis weights are produced by Exponentiated Gradient on the simplex, and the
deliberation emphasis is `exp(A·tanh(k·ln(w_learned/w_seed)))` — a tanh in log-ratio space.
This shape is an **engineering choice** that is *consistent with* (not a verbatim
implementation of) the following verified results:
- **Kivinen & Warmuth (1997)** — "Exponentiated Gradient versus Gradient Descent for Linear
  Predictors," *Information and Computation* 132(1):1–63, DOI:10.1006/inco.1996.2612. The EG
  algorithm: multiplicative simplex-constrained weight updates (the L3 learner we use).
- **Aitchison (1982)** — "The Statistical Analysis of Compositional Data," *JRSS-B* 44(2):139–177,
  DOI:10.1111/j.2517-6161.1982.tb01195.x (review: **Greenacre et al. 2022**, *Statistical Science* 37(3)). Log-ratio is the natural
  geometry for simplex-valued data → the `ln(w_learned/w_seed)` divergence.
- **Brooks, Chodrow & Porter (2024)** — "Emergence of Polarization in a Sigmoidal
  Bounded-Confidence Model of Opinion Dynamics," *SIAM J. Appl. Dyn. Syst.* 23:1442–1470,
  [arXiv:2209.07004](https://arxiv.org/abs/2209.07004), DOI:10.1137/22M1527258. Replaces the HK **hard cutoff** with a smooth
  sigmoidal influence function (steepness γ) → precedent for "smooth, not hard, influence."
- **Sampson, Restrepo & Porter (2025)** — "Oscillatory and Excitable Dynamics in an Opinion
  Model with Group Opinions," *Phys. Rev. E* 112:024303, [arXiv:2408.13336](https://arxiv.org/abs/2408.13336),
  DOI:10.1103/PhysRevE.112.024303. A recent opinion model using a smooth (tanh-type) influence
  kernel → precedent for a tanh saturation in opinion dynamics.
- **Latané (1981)** — "The Psychology of Social Impact," *American Psychologist* 36(4):343–356,
  DOI:10.1037/0003-066X.36.4.343 (dynamic follow-up: **Nowak, Szamrej & Latané 1990**,
  *Psychological Review* 97(3)). Social impact is **sublinear** in source intensity
  (`I ∝ N^t, t<1`): influence has diminishing marginal returns → the *saturating character*
  of the emphasis bound. We share the saturation character, not the functional form.

## Trust dynamics / adaptive decay
- **Abdul-Rahman & Hailes (2000)** — "Supporting Trust in Virtual Communities," *HICSS-33*.
  Reputation/word-of-mouth trust.
- **Mohseni & Bernstein (2022)** — "Recursive Least Squares with Variable-Rate Forgetting
  Based on the F-Test," *American Control Conference* —
  <https://dsbaero.engin.umich.edu/wp-content/uploads/sites/441/2022/10/MohseniFtestACC2022.pdf>.
  Variable-rate forgetting → the adaptive per-dyad trust decay. *(An earlier PR-body draft
  mislabeled this entry's title as "adaptive bounded-confidence in polarised networks"; that is
  a different paper — Kan, Feng & Porter (2023), arXiv:2112.05856 — corrected 2026-07-02.)*
- **Arena, Mulder & Leenders (2023)** — "How fast do we forget our past social interactions?
  …parametric decays in relational event models," *Network Science* 11(2), DOI:10.1017/nws.2023.5.
  Exponential decay best-fits social-interaction memory → the `_TRUST_DECAY` half-life.
- **den Boer, Meylahn & Mandjes (2024)** — "Interpersonal Trust: Asymptotic Analysis of a
  Stochastic Coordination Game with Multi-Agent Learning," *Chaos* 34 (2024),
  DOI:10.1063/5.0205136. Agents update trust via an exponential moving average of past
  interactions → grounds the `gain < 1−decay` stability constraint. *(Verified 2026-06-30: the
  earlier arXiv id `2303.01921` we carried is the WRONG paper — that id is "Trusting: Alone and
  Together," unrelated — so it has been removed; cite the* Chaos *journal version. The Arena et
  al. 2023 entry below independently anchors the exponential-decay/forgetting choice.)*

## Loss aversion / negativity bias (gain:loss ratio)
- **Martínez-Tomás, Molins & Serrano (2022)** — "Implicit Negativity Bias Leads to Greater
  Loss Aversion and Learning during Decision-Making," *IJERPH* 19(24):17037,
  DOI:10.3390/ijerph192417037 — <https://www.ncbi.nlm.nih.gov/pmc/articles/PMC9779195/>.
  Supports the negativity-bias → loss-aversion *link*; it does not itself give a numerical λ.
- **Tversky & Kahneman (1992)** — "Advances in Prospect Theory," *J. Risk and Uncertainty*
  5:297–323, DOI:10.1007/BF00122574 — the source of the classic λ ≈ 2.25 estimate.
  **Honest range:** the loss:gain ratio is not a single universal constant — Tversky & Kahneman
  (1992) estimate λ ≈ 2.25, while **Bleichrodt & L'Haridon (2023)** ("A new test of loss
  aversion," DOI:10.1017/jdm.2023.2) find λ ≈ 1.25–1.45 controlling for diminishing sensitivity.
  Our `_TRUST_LOSS/_TRUST_GAIN ≈ 2.5` sits at the high (T&K) end; we cite the range, not a single
  value.

## Affective / epistemic representation
- **Russell (1980)** — "A Circumplex Model of Affect," *J. Personality and Social Psychology*
  39(6):1161–1178. The valence × arousal `_affective` axis.

## Coalition / deliberation quality (trajectory types)
- **Leifeld & Brandenberger (2024)** — endogenous coalition formation in policy debates
  (Discourse Network Analysis; preprint [arXiv:1904.05327](https://arxiv.org/abs/1904.05327) —
  <https://arxiv.org/abs/1904.05327>). Bonding via repeated co-participation → the co-commit
  ledger and the `coalitional` trajectory type.
- **Agarwal & Khanna (2025)** — "When Persuasion Overrides Truth in Multi-Agent LLM
  Debates," [arXiv:2504.00374](https://arxiv.org/abs/2504.00374). Agents converge on a
  *persuasive* but wrong answer — "agree more while knowing less." This is the **primary,
  verifiable anchor** for `evidence_delta` and the `fragile` / `coerced` consensus types as a
  per-round audit signal that distinguishes genuine persuasion from sycophantic capitulation.
  *(An earlier draft cited a "Deliberative Illusion / Wan et al. 2026" title from the project
  deep-research survey for which no public arXiv/DOI could be located; it is dropped in favour
  of this verifiable citation rather than retained as an unverifiable reference.)*

## Consensus quality audit — genuine vs superficial agreement (`consensus_quality`)
The `independence_rate` / `capitulation_rate` / `disagreement_collapse` metrics are grounded in
(all verified 2026-06-30):
- **Weng, Chen & Wang (2025)** — "Do as We Do, Not as You Think: the Conformity of Large
  Language Models," [arXiv:2501.13381](https://arxiv.org/abs/2501.13381) (ICLR 2025 Oral). BenchForm's **conformity / independence
  rate** → our `independence_rate`.
- **Yao et al. (2025)** — "Peacemaker or Troublemaker: How Sycophancy Shapes Multi-Agent
  Debate," [arXiv:2509.23055](https://arxiv.org/abs/2509.23055). Formalizes sycophancy / **disagreement collapse** in multi-agent
  debate → our `disagreement_collapse`.
- **Agarwal & Khanna (2025)** — CW-POR ([arXiv:2504.00374](https://arxiv.org/abs/2504.00374), above): confidence-weighted
  persuasion-without-evidence → our `capitulation_rate` (moved while peer-relative confidence
  pull was negative).

## Related multi-agent-consensus systems (positioning; verified 2026-06-30)
None pairs *embedding-valued* opinions + *temporal* tracking + a *BFT* commit + a
*genuine-vs-superficial* quality audit — each covers only part of the pipeline:
- **Ruan, Wang et al. (2025)** — "Reaching Agreement Among Reasoning LLM Agents" (Aegean),
  [arXiv:2512.20184](https://arxiv.org/abs/2512.20184). Formal safety+liveness via incremental quorum; **no** semantic opinion
  representation, temporal model, or quality audit.
- **Chang (2024)** — "EVINCE," [arXiv:2408.14575](https://arxiv.org/abs/2408.14575). Info-theoretic (entropy/Wasserstein) debate
  regulation; **no** BFT guarantee or per-agent sycophancy score.
- **Chen, Ji, Xu & Zhao (2023)** — "Multi-Agent Consensus Seeking via LLMs," [arXiv:2310.20151](https://arxiv.org/abs/2310.20151).
  Scalar-state averaging consensus; **no** BFT, vectors, or audit.

## Multidimensional opinion dynamics (the 5-axis regime)
- **Fortunato, Latora, Pluchino & Rapisarda (2005)** — "Vector Opinion Dynamics in a Bounded
  Confidence Consensus Model," *IJMPC* 16:1535–1551, arXiv:physics/0504017. **Free real-valued
  vector** opinions: consensus thresholds are close to the 1-D case, dimensions roughly
  independent — this is the regime our (free, per-axis-normalized) 5-axis vector lives in. Our
  lower 5-D threshold (0.60) is an **empirical calibration**, not a claim about dimensionality.
- **Lorenz (2007)** — "Continuous opinion dynamics of multidimensional allocation problems…,"
  [arXiv:0708.2923](https://arxiv.org/abs/0708.2923). **Simplex/allocation** opinions (sum-to-1): higher dimensions help consensus.
  Cited for context only — its result is allocation-specific and does NOT apply to our free
  vectors, so we deliberately do not use it to justify our threshold.

## Embedding-based opinion representation (semantic axis: pluggable, defaults to bag-of-words)
- **Gatto, Sharif & Preum (2023)** — "Chain-of-Thought Embeddings for Stance Detection on
  Social Media," EMNLP 2023, [arXiv:2310.19750](https://arxiv.org/abs/2310.19750). Embedding the reasoning trace (not just the
  final label) for robust stance. The plugin exposes an **implemented** `embed_fn` injection
  point (`ResonanceBFT(..., embed_fn=...)`): inject any dense encoder (e.g. a sentence-
  transformer, or CoT-trace embeddings per Gatto et al.) to make the semantic axis a fixed-dim
  dense vector. Because the semantic vector is sealed at participate() and never recomputed at
  commit, this does NOT affect resolver-independence (covered by tests). The default remains
  bag-of-words so the plugin stays drop-in with no heavy ML dependency; shipping a *specific*
  pretrained model is a deployment choice, not bundled here.

## Stance / agreement-polarity representation (`_polarity.py` — the stance audit)

Background: `BENCHMARKS.md` shows cosine over a single semantic vector cannot separate
*stance* — "approve the proposal" vs "reject the proposal" score ~0.8 similar because they
are topically identical (a known phenomenon: topic–stance conflation / pretrained stance
bias). The polarity probe recovers stance as a signed projection onto an antonym-anchored
direction; the `false_agreement` consensus-quality signal uses it to flag a quorum that is
cosine-aligned yet stance-split. All citations verified 2026-06-30.

- **Park, Choe & Veitch (2024)** — "The Linear Representation Hypothesis and the Geometry of
  Large Language Models," ICML 2024, [arXiv:2311.03658](https://arxiv.org/abs/2311.03658). Formalizes that high-level concepts
  (including polarity/approval) are encoded as **linear directions**, extractable as probes /
  steering vectors. *How we use it:* the theoretical grounding for reading stance as a signed
  projection onto an antonym-anchored polarity direction (`_polarity.stance_scalar`) rather
  than off raw cosine.
- **Engler, Sikdar, Lutz & Strohmaier (2023)** — "SensePOLAR: Word-sense aware interpretability
  for pre-trained contextual word embeddings," [arXiv:2301.04704](https://arxiv.org/abs/2301.04704). Extracts interpretable polar
  dimensions from contextual embeddings by **antonym-pair anchoring** (good↔bad, approve↔reject).
  *How we use it:* the concrete recipe for `_polarity.polarity_direction` — embed fixed PRO/CON
  antonym lists, take the normalised centroid difference as the polarity axis (no training).
- **Burnham (2023/2025)** — "Stance Detection: A Practical Guide to Classifying Political Beliefs
  in Text," *PSRM*, [arXiv:2305.01723](https://arxiv.org/abs/2305.01723). Distinguishes stance from sentiment and advocates NLI-style
  (joint utterance+target) classification, which sidesteps the cosine-conflation problem.
  *How we use it:* positioning — documents why a single-vector cosine is the wrong tool for
  agreement, and the pairwise-NLI alternative we record as a heavier optional path (not shipped).
- **Hanley & Durumeric (2023)** — "TATA: Stance Detection via Topic-Agnostic and Topic-Aware
  Embeddings," [arXiv:2310.14450](https://arxiv.org/abs/2310.14450). Contrastively factorizes topic-agnostic (stance) from
  topic-aware embeddings. *How we use it:* cited as the train-required alternative to our
  zero-training antonym-anchored probe; motivates keeping topic on the semantic axis and stance
  on the sign-carrying axes.
- **NLI cross-encoder, no-torch tier** — `Xenova/nli-deberta-v3-small` (ONNX port of
  cross-encoder DeBERTa-v3 NLI), run via `onnxruntime` + `tokenizers` (no PyTorch).
  Reads two utterances *jointly with cross-attention* and classifies entailment /
  contradiction / neutral. *How we use it:* the optional high-accuracy stance tier
  benchmarked in `examples/resonance_bft_embeddings/nli_vs_probe.py` — measured to tie
  the linear probe on explicit approve/reject and to win 6/6 vs 0/6 on hard
  (negation / implicit / off-axis) stance, because cross-attention can model what a
  single-vector projection cannot.  Not wired into the commit path (pairwise, O(n²));
  it is an analyzer, while the probe is the resolver-independent in-protocol audit.
- **Altafini (2012)** — "Dynamics of Opinion Forming in Structurally Balanced Social Networks,"
  *PLoS ONE* 7(6):e38135, doi:10.1371/journal.pone.0038135. Signed-graph opinion dynamics:
  negative ties produce **repulsive** dynamics and bipartite consensus. *How we use it:* the
  theoretical basis for treating disagreement as a *sign* (future relational-axis work: allow
  negative trust → repulsive influence), referenced in the stance deep-research report.

---
*Each entry here was independently verified against arXiv / DOI / the authors' publication lists
(the inline notes record where an earlier automated literature survey had an id or title wrong and
how it was corrected). A few code comments use shortened author-year tags; this file is the
authoritative, link-bearing version.*
