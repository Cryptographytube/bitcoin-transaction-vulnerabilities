# 🔐 Bitcoin Transaction-Level Vulnerabilities — Complete Research Taxonomy

### Signature Math, Consensus, Network, Privacy, Lightning \& Wallet Attack Surface

⚠️ Ethical / Legal Disclaimer



This article is purely for educational purposes and defensive security research.

Only test on your own keys / testnet / authorized bug-bounty targets.

Accessing someone else's funds, even if the key is mathematically recoverable, is theft and a criminal offense in almost every country.

Responsible disclosure is the only legitimate path: vendor → security@/bug bounty → coordinated disclosure.

## 📌 Overview

Bitcoin's core protocol has never been mathematically "hacked" to date — but the transaction signing layer, consensus rules, P2P network, and wallet implementations have considerable attack surfaces. This document organizes 150+ distinct vulnerabilities/attack classes into 8 layers:

|Section|Layer|Approx. Items|
|-|-|-|
|A|Signature Math (ECDSA/Schnorr)|28|
|B|Transaction Format \& Consensus|19|
|C|P2P Network / Node|16|
|D|Double-Spend / Mining Strategy|14|
|E|Privacy|17|
|F|Lightning Network / L2|13|
|G|Wallet / Key Management|15|
|H|Historical CVEs (Bitcoin Core)|14+|

> \\\\\\\*\\\\\\\*Note:\\\\\\\*\\\\\\\* 1More than 50 variants are included in the count. There are approximately 40–50 distinct root primitives — the rest are their variations, optimizations, or layer-specific instances

\---

## 🔴 Section A — Signature Math Layer (ECDSA / Schnorr)

This is the layer where private keys are derived using pure mathematics. The most dangerous section.

### A.1 Nonce (k) Reuse — The Classic

Bitcoin ECDSA signature: `s = k⁻¹(z + r·d) mod n`

If two signatures. same nonce `k` ho (same `r`):

```
k  = (z₁ − z₂) · (s₁ − s₂)⁻¹ mod n
d  = (s₁·k − z₁) · r⁻¹ mod n     ← private key recovered
```

|#|Variant|Reality|
|-|-|-|
|1|Full nonce reuse (same tx)|🔴 Trivially exploitable|
|2|Cross-transaction nonce reuse|🔴 Trivially exploitable — r-value blockchain pe public hai|
|3|Partial nonce reuse (shared MSB/LSB blocks)|🟠 Lattice se solvable|
|4|Nonce reuse across chains (BTC/BCH/altcoins)|🔴 Same key + same k = key on all chains|

**Real incidents:**

* **Sony PS3 (2010)** — constant `k` in every signature → ECDSA private key recovered
* **Blockchain.info RNG bug (Aug 2013)** — thousands of BTC stolen via duplicate `k`
* **Android SecureRandom bug (2013)** — biased `k` on Android wallets

### A.2 Biased / Partial Nonce Leaks → HNP + Lattice

If some bits of the nonce are known or biased, the problem becomes a Hidden Number Problem (HNP):

```
k = (z + r·d)/s   →   a·k + r·d ≈ b (mod n)   ← HNP form
```

Solved via **Howgrave-Graham–Smart lattice attack** / **Bleichenbacher's method** using LLL/BKZ reduction:

|#|Variant|Known bits needed (approx.)|
|-|-|-|
|5|LSB bias (4 bits known)|\~100–200 signatures|
|6|MSB bias / fixed upper bits|similar order|
|7|Middle bits known|lattice, harder construction|
|8|Short nonce (< 256-bit truncation)|as good as full leak if < 128-bit|
|9|Fixed prefix/suffix nonce|reduces keyspace drastically|
|10|Counter-based nonce (k, k+1, k+2...)|🔴 catastrophic|
|11|Linear related nonces (k₂ = a·k₁ + b)|lattice-solvable|
|12|Naive k = H(message) or k = H(key)|🔴 trivially computable by anyone|
|13|k = H(z) reused across different keys|🔴 key recovered instantly|

**Real incidents:**

* **Minerva (2019, CVE-2019-15809)** — smartcards produced variable-bit-length nonces → lattice attack → key recovery (affected crypto hardware incl. some used for coins)
* **TPM-Fail (CVE-2019-11090)** — Intel fTPM ECDSA timing side-channel leaked nonce MSB
* **Biased Nonce Sense** (Breitner \& Heninger, 2019) — internet-wide scan: hundreds of BTC recovered from weak nonces in the wild

### A.3 Deterministic Nonce (RFC 6979) Failure Modes

|#|Bug|Consequence|
|-|-|-|
|14|Weak/missing `additional data` entropy|Deterministic but predictable|
|15|`bits2octets` step skipped|k occasionally out of range/biased|
|16|mod-n reduction error in implementation|biased k → lattice attack|

### A.4 Fault Injection \& Physical

|#|Attack|Mechanism|
|-|-|-|
|17|Bit-flip during signing (voltage glitch / laser / EM)|One faulty sig + one valid sig → d recovered via: from (r, s) valid and (r', s') faulty, subtract the two equations|
|18|Rowhammer on signing machine|Same class|
|19|Rowhammer-based nonce flipping|Induces k bias|
|20|Power/EM analysis (SPA/DPA) on hardware wallets|Bit-by-bit nonce recovery|

### A.5 Curve-Level

|#|Attack|Note|
|-|-|-|
|21|Invalid curve attack|No point validation → key chunks leak per query|
|22|Quadratic twist attack|secp256k1 twist order \~2^128 — practically hard but theoretically documented|
|23|Missing r,s edge validation (r=0, s=0, r≥n)|Implementation bypass|

### A.6 Schnorr / Taproot Era (BIP-340)

|#|Attack|Consequence|
|-|-|-|
|24|Schnorr nonce reuse|Instant key leak — even simpler than ECDSA case|
|25|MuSig1 nonce without pubkey commitment|Co-signer can steal via Wagner attack|
|26|MuSig2 insecure nonce aggregation|Wagner's generalized birthday attack on 256-bit? (MuSig2 paper documents secure construction precisely for this)|
|27|Kleptographic nonce exfiltration via crafted R|Malicious signer embeds encrypted key share in R|
|28|Deterministic nonce grind (R tweaked until metadata leaks)|Covert channel in signatures|

\---

## 🟠 Section B — Transaction Format \& Consensus Layer

|#|Vulnerability|Status / Note|
|-|-|-|
|29|Signature malleability (s → n−s)|✅ Fixed via BIP-62 / LOW-S (BIP-146)|
|30|Script malleability (pre-BIP-62 push encodings)|✅ Fixed|
|31|OpenSSL non-strict DER malleability|✅ BIP-66 (2015)|
|32|NULLDUMMY bug — extra stack item in CHECKMULTISIG|✅ BIP-146|
|33|**CVE-2018-17144 — duplicate input** (inflation!)|✅ Fixed 2018 — worst bug since 2010, silently exploited impossible due to honest majority|
|34|**CVE-2010-5137 — value overflow** (184 billion BTC event, block 74638 rollback)|✅ Fixed|
|35|SIGHASH\_SINGLE out-of-range input index → sighash = 1|⚠️ Quirk still exists (BIP-143 alt)|
|36|SIGHASH\_SINGLE \| ANYONECANPAY output mismatch|⚠️ Wallet implementation foot-gun|
|37|Anyone-can-spend outputs (OP\_TRUE misconfig)|⚠️ Wallet error|
|38|P2SH redeem-script collision|Theoretical (160-bit), wallet misuse realistic|
|39|SegWit txid vs wtxid confusion|Third-party witness malleability of txid for unconfirmed|
|40|Taproot script-path leaf malleability (non-canonical serialization)|⚠️ Taproot-specific|
|41|Taproot annex misuse|⚠️ Implementation-defined behavior|
|42|Keypath/scriptpath ambiguity bugs in wallet signing|⚠️ Real-world wallet bugs|
|43|**Timewarp attack** — difficulty manipulation via MTP|⚠️ Theoretical on BTC; exploited on testnet-like chains|
|44|Consensus split via differing validation rules|Historical (2013 BDB fork)|
|45|Block timestamp manipulation (MTP edge, +2h limit)|⚠️ Miner-level|
|46|**CVE-2012-2459 — merkle tree tx duplication**|✅ Fixed|
|47|OP\_RETURN / provably-unspendable misuse (data bloat)|By design, DoS-vector debates|
|48|CHECKMULTISIG stack bug in alt-implementations|Interop risk|

\---

## 🟡 Section C — P2P Network / Node Layer

|#|Attack|Note|
|-|-|-|
|49|Eclipse attack (isolate node, feed fake view)|🔴 Real; strongest vs mobile/light nodes|
|50|AS-aware eclipse / **EREBUS** (BGP-level partition)|🔴 Research-demonstrated|
|51|BGP hijack on pools / large nodes|Real-world incidents (2014, 2018 hijacks)|
|52|DNS seed poisoning|Mitigated: hardcoded seeds + randomization|
|53|Address gossip poisoning (addr flooding)|Mitigated: addrman bucketing|
|54|Spy-node transaction origin inference|🔴 Practical privacy break for light clients|
|55|Dandelion++ stem inference flaws|🟠 Partial mitigations exist|
|56|Tor-only node de-anonymization (traffic correlation)|🟠 If attacker controls entry+exit|
|57|Feeler connection fingerprinting|🟡|
|58|Node fingerprinting via mempool policy differences|🟡|
|59|INV/GETDATA withholding (selective tx delay)|🟡|
|60|Block withholding between peers|🟡|
|61|**Timejacking** (NTP spoof → median time drift → fork risk)|🟠 Requires network position|
|62|Compact block / FIBRE relay interception|🟡|
|63|Connection-slot Sybil flooding (100% eclipse, pre-2015)|✅ Mitigated (evict, per-net groups, anchors)|
|64|Mempool partitioning / censorship by policy|🟡 Ongoing research area|

\---

## 🟢 Section D — Double-Spend / Mining Strategy

|#|Attack|Preconditions|
|-|-|-|
|65|Race attack (0-conf)|Merchant accepts 0-conf|
|66|Finney attack|Attacker is a miner|
|67|Vector76 (Finney + race hybrid)|Miner + timing|
|68|Alternative history / deep reorg double-spend|Hashpower share|
|69|**51% attack**|Majority hashpower — done on ETC, BTG; impractical on BTC|
|70|Selfish mining (Eyal \& Sirer 2014)|> 1/3 under favorable conditions|
|71|Stubborn mining variants|Extension of #70|
|72|Block withholding (FPoW) on pools|Pool-level|
|73|Fork-After-Withholding (FAW)|Pool-level, more profitable than BWH|
|74|Pool hopping (difficulty window gaming)|Legacy pools|
|75|Stratum v1 exploits (no auth, man-in-middle)|✅ Stratum v2 fixes|
|76|Transaction pinning|L2 context|
|77|RBF pinning / fee-bump griefing|L2 + mempool policy|
|78|Time-dilation on LN (eclipse + delayed blocks)|🔴 Practical combo shown in research|

\---

## 🔵 Section E — Privacy Layer

|#|Heuristic / Attack|
|-|-|
|79|Address reuse linkability|
|80|Common-input-ownership heuristic (clustering)|
|81|Change-address detection (fresh address, round amounts)|
|82|Round-amount heuristic|
|83|Peeling-chain detection|
|84|UTXO-merge linkage (broken CoinJoin hygiene)|
|85|**BIP-37 bloom filter leakage** (CVE-class privacy disaster for SPV)|
|86|Mempool sniffing (unconfirmed tx tracking)|
|87|Value fingerprinting correlation|
|88|Spend-time clustering|
|89|NetFlow / ISP-level traffic analysis|
|90|CoinJoin post-mix heuristics ( denomination analysis)|
|91|PayJoin misidentification by server|
|92|Dust attack (forced address linkage)|
|93|Electrum/server query correlation (light clients leak full xpub history)|
|94|xpub upload to third-party servers|
|95|Lightning channel-graph probing (balance deanonymization)|

\---

## 🟣 Section F — Lightning Network / L2

|#|Attack|
|-|-|
|96|Old channel-state broadcast (breach attempt) — countered by penalty, but race exists|
|97|Griefing attack (HTLC lockup, capital freeze)|
|98|Flood \& Loot (mass force-close during fee spike)|
|99|HTLC preimage malleability issues|
|100|Channel-reserve griefing|
|101|Time-lock expiry manipulation|
|102|Slot \& channel jamming|
|103|Probing attack (balance discovery)|
|104|Eclipse + old-state broadcast combo|
|105|Watchtower data unavailability|
|106|CPFP/anchor-output pinning on force-close (**CVE-2021-31876** class)|
|107|Dual-funded channel race conditions|
|108|Revocation-key derivation implementation bugs|

\---

## ⚫ Section G — Wallet / Key Management

|#|Bug / Attack|
|-|-|
|109|Brainwallet weak entropy (passphrase → key)|
|110|Mnemonic generation with insufficient entropy|
|111|Weak 25th-word passphrase (human entropy)|
|112|Derivation-path confusion → fund loss|
|113|xpub/seed leakage via cloud backups, photos|
|114|Multisig ceremony failure (threshold misconfig)|
|115|SLIP-39 share misconfiguration|
|116|Hardware wallet RNG failures (lattice-vulnerable class)|
|117|Hot-wallet key material in swap/logs|
|118|Clipboard hijack (address swap)|
|119|PSBT signing of wrong input/tx|
|120|QR exfiltration on air-gapped setups|
|121|Supply-chain backdoored hardware wallets|
|122|Cross-chain key reuse (BTC + forks + ETH same keys)|
|123|BIP-32 seed from bad RNG (2013 Blockchain.info class)|

\---

## ⚪ Section H — Historical CVEs (Bitcoin Core, selected)

|CVE|Year|Description|
|-|-|-|
|CVE-2010-5137|2010|Value overflow — 184B BTC, chain rollback fix|
|CVE-2010-5138|2010|Script opcode remapping|
|CVE-2010-5139|2010|Tx malleability (pre-0.6.0)|
|CVE-2012-2459|2012|Merkle tree duplicate-tx block validation flaw|
|CVE-2013-2292|2013|Large block DoS / 91842-91880 fork (BDB locks)|
|CVE-2013-4627|2013|Unconfirmed-tx spoofing via bloom|
|CVE-2013-5700|2013|UnspentOutputCache DoS|
|CVE-2014-6426 et al.|2014|Orphan-tx handling / RPC DoS family|
|CVE-2016-10724/10725|2016|Context-dependent sigops DoS / map overflow DoS|
|CVE-2017-12842|2017|SPV proof forgery below 80 bytes (SPV clients)|
|CVE-2018-17144|2018|**Duplicate input — inflation bug**|
|CVE-2018-17145|2018|Rapid RPC crash DoS|
|CVE-2020-14198|2020|Private keys leaked via debug logs on `encryptwallet` crash path|
|CVE-2021-31876|2021|CPFP carve-out exemption — L2 pinning vector|
|Bech32 QR mutation|2021|Bech32 doesn't catch certain mutation characters in QR context (disclosed by RobinLinus)|

\---

## 📊 The Reality Check

|Claim|Fact|
|-|-|
|"Bitcoin protocol hacked"|❌ Never — losses are wallets, exchanges, implementations|
|"150+ vulns"|⚠️ Counting variants: yes. Distinct root primitives: \~40–50|
|Sab key theft?|❌ Only Section A (items 1–28) → private key via math. Baaki DoS/privacy/protocol-level|
|Greatest live risk today|🔥 RNG failure + lattice attacks (automated scanners still find compromised keys on-chain)|
|Quantum|⚠️ Future threat to exposed pubkeys (Shor). P2PKH hides pubkey behind HASH160 until spend|

\---

## 🎯 Active Research / Whitehat Hunting Grounds (2026)

1. **Biased nonce scanning** — HNP/lattice tooling (`polynonce`-class) against the chain; responsible disclosure route
2. **MuSig2 / FROST implementation audits** — Taproot multisig is young
3. **Lightning pinning attacks** — CVE-2021-31876 class still relevant with anchors
4. **Stratum v2 transition gaps** — mixed v1/v2 deployments
5. **Privacy heuristics** — CoinJoin/PayJoin post-mix leakage research

\---

## 📚 Key References

* Breitner \& Heninger — *"Biased Nonce Sense: Lattice Attacks against Weak ECDSA Signatures in Cryptocurrencies"* (2019)
* Castelluccia et al. — *"Minerva: The curse of ECDSA nonces"* (2019)
* TPM-Fail — Moghimi et al. (2020)
* Eyal \& Sirer — *"Majority is not Enough: Bitcoin Mining is Vulnerable"* (2014)
* Heilman et al. — *"Eclipse Attacks on Bitcoin's P2P Network"* (2015)
* Tran et al. — *"A Stealthier Partitioning Attack against Bitcoin P2P Network"* (EREBUS, 2020)
* Nayak et al. — *"Stubborn Mining"* (2016)
* Harris \& Zohar — *"Flood \& Loot: A Systemic Attack On The Lightning Network"* (2020)
* Mizrahi \& Zohar — *"Congestion Attacks in Payment Channel Networks"* (2021)
* BIP-340/341/342 (Taproot/Schnorr), BIP-62, BIP-66, BIP-146, BIP-147
* bitcoincore.org security advisories

\---

