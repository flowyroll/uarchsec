# Attack
## CPU
### Cache
* [Cache Attacks and Countermeasures: the Case of AES](https://www.cs.tau.ac.il/~tromer/papers/cache.pdf)
* [Cache missing for fun and profit](http://www.daemonology.net/papers/cachemissing.pdf)
* [Cache-timing attacks on AES](https://cr.yp.to/antiforgery/cachetiming-20050414.pdf)
### Last-Level Cache (LLC)
* [FLUSH+RELOAD: a High Resolution, Low Noise, L3 Cache Side-Channel Attack](https://www.usenix.org/system/files/conference/usenixsecurity14/sec14-paper-yarom.pdf)
* [Last-Level Cache Side-Channel Attacks are Practical](http://palms.ee.princeton.edu/system/files/SP_vfinal.pdf)
* [S $ A: A shared cache attack that works across cores and defies VM sandboxing--and its application to AES](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.699.6655&rep=rep1&type=pdf)
* [Attack Directories, Not Caches: Side-Channel Attacks in a Non-Inclusive World](http://iacoma.cs.uiuc.edu/iacoma-papers/ssp19.pdf)
* [Flush+ Flush: a fast and stealthy cache attack](https://arxiv.org/pdf/1511.04594.pdf)
### Branch Prediction
* [On the Power of Simple Branch Prediction Analysis](http://cryptome.org/sbpa.pdf)
* [Predicting Secret Keys Via Branch Prediction](https://eprint.iacr.org/2006/288.pdf)
* [Jump Over ASLR: Attacking Branch Predictors to Bypass ASLR](http://www.cs.binghamton.edu/~secarch/micro16.pdf)
* [BranchScope: A New Side-Channel Attack on Directional Branch Predictor](https://www.pbwcz.cz/Pocitacovy%20utok/CPU/BranchScopeAttack.pdf)
* [Understanding and Mitigating Covert Channels Through Branch Predictors](http://www.cs.binghamton.edu/~dima/taco16_branches.pdf)
### TSX
* [Breaking Kernel Address Space Layout Randomization with Intel TSX](https://sslab.gtisc.gatech.edu/assets/papers/2016/jang:drk-ccs.pdf)
* [Prime+Abort: A Timer-Free High-Precision L3 Cache Attack using Intel TSX](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-disselkoen.pdf)
#### Spectre
* [Spectre Attacks: Exploiting Speculative Execution](https://spectreattack.com/spectre.pdf)
* [ret2spec: Speculative Execution Using Return Stack Buffers](https://christian-rossow.de/publications/ret2spec-ccs2018.pdf)
* [Spectre Returns! Speculation Attacks using the Return Stack Buffer](https://arxiv.org/abs/1807.07940)
### Memory Ordering
* [MemJam: A False Dependency Attack against Constant-Time Crypto Implementations](https://arxiv.org/pdf/1711.08002.pdf)
* [Microarchitectural Minefields: 4K-Aliasing Covert Channel and Multi-Tenant Detection in IaaS Cloud](http://jin.ece.ufl.edu/papers/NDSS18.pdf)
### Instruction Cache
* [New Results on Instruction Cache Attacks](https://pdfs.semanticscholar.org/b028/22567d583b89acc0b2bd5afa417ffa835d0a.pdf)
* [Yet another MicroArchitectural Attack:: exploiting I-Cache](http://palms.ee.princeton.edu/system/files/icache_onur07.pdf)
### Cache Bank
* [CacheBleed: A Timing Attack on OpenSSL Constant Time RSA](https://eprint.iacr.org/2016/224.pdf)
### SGX
* [CacheZoom: How SGX Amplifies the Power of Cache Attacks](https://eprint.iacr.org/2017/618.pdf)
* [Software grand exposure: SGX cache attacks are practical](https://www.usenix.org/system/files/conference/woot17/woot17-paper-brasser.pdf)
* [Inferring Fine-grained Control Flow Inside SGX Enclaves with Branch Shadowing](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-lee-sangho.pdf)
* [Malware Guard Extension: Using SGX to Conceal Cache Attacks](https://arxiv.org/pdf/1702.08719.pdf)
### Page Table
* [Controlled-Channel Attacks: Deterministic Side Channels for Untrusted Operating Systems](https://www.ieee-security.org/TC/SP2015/papers-archived/6949a640.pdf)
* [Telling Your Secrets Without Page Faults: Stealthy Page Table-Based Attacks on Enclaved Execution](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-van_bulck.pdf)
#### Translation Leak-aside Buffer (TLB)
* [Translation Leak-aside Buffer: Defeating Cache Side-channel Protections with TLB Attacks](https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-gras.pdf)
### Interrupt / Exception 
* [Nemesis: Studying Microarchitectural Timing Leaks in Rudimentary CPU Interrupt Logic](https://distrinet.cs.kuleuven.be/software/sancus/publications/ccs18.pdf)
* [Meltdown: Reading Kernel Memory from User Space](https://meltdownattack.com/meltdown.pdf)
* [FORESHADOW: Extracting the Keys to the Intel SGX Kingdom with
Transient Out-of-Order Execution](https://foreshadowattack.eu/foreshadow.pdf)
### Prefetching
* [Prefetch Side-Channel Attacks: Bypassing SMAP and Kernel ASLR](https://gruss.cc/files/prefetch.pdf)
* [Unveiling Hardware-based Data Prefetcher, a Hidden Source of Information Leakage](https://dl.acm.org/citation.cfm?id=3243736)
### Floating-point Unit
* [LazyFP: Leaking FPU Register State using Microarchitectural Side-Channels](https://blog.cyberus-technology.de/images/lazyFP.pdf)
* [On Subnormal Floating Point and Abnormal Timing](http://www.ieee-security.org/TC/SP2015/papers-archived/6949a623.pdf)
### PRNG
* [Covert Channels through Random Number Generator: Mechanisms, Capacity Estimation and Mitigations](http://www.cs.binghamton.edu/~dima/ccs16.pdf)
## ARM
* [ARMageddon: Cache Attacks on Mobile Devices](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_lipp.pdf)
* [AutoLock: Why Cache Attacks on ARM Are Harder Than You Think](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-green.pdf)
* [Return-Oriented Flush-Reload Side Channels on ARM and Their Implications for Android Device](http://web.cse.ohio-state.edu/~zhang.834/papers/ccs16b.pdf)
## DRAM
* [DRAMA: Exploiting DRAM Addressing for Cross-CPU Attacks](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_pessl.pdf)
### Rowhammer
* [Another Flip in the Wall of Rowhammer Defenses](https://arxiv.org/pdf/1710.00551.pdf)
* [Exploiting Correcting Codes: On the Effectiveness of ECC Memory Against Rowhammer Attacks](http://cs.vu.nl/~lcr220/ecc/ecc-rh-paper-sp2019-cr.pdf)
* [Flipping bits in memory without accessing them: an experimental study of DRAM disturbance errors](http://users.ece.cmu.edu/~yoonguk/papers/kim-isca14.pdf)
### ARM
* [Drammer: Deterministic Rowhammer Attacks on Mobile Platforms](https://gruss.cc/files/drammer.pdf)
## JavaScript
* [Fantastic Timers and Where to Find Them: High-Resolution Microarchitectural Attacks in JavaScript](https://gruss.cc/files/fantastictimers.pdf)
* [Rowhammer.js: A Remote Software-Induced Fault Attack in JavaScript](http://arxiv.org/abs/1507.06955)
* [The Spy in the Sandbox: Practical Cache Attacks in JavaScript and their Implications](http://www.cs.columbia.edu/~simha/spyjs.ccs15.pdf)
* [Drive-by Key-Extraction Cache Attacks from Portable Code](https://eprint.iacr.org/2018/119.pdf)
## GPU
* [Rendered Insecure: GPU Side Channel Attacks are Practical](https://www.cs.ucr.edu/~zhiyunq/pub/ccs18_gpu_side_channel.pdf)
* [Grand Pwning Unit: Accelerating Microarchitectural Attacks with the GPU](https://www.vusec.net/wp-content/uploads/2018/05/glitch.pdf)
## FPGA
* [FPGA Side Channel Attacks without Physical Access](http://www.ecs.umass.edu/ece/tessier/ramesh-fccm18.pdf)
* [FPGA-Based Remote Power Side-Channel Attacks](https://sites.coecis.cornell.edu/edsuh/files/2018/04/SP2018-FPGA-2m12dnp.pdf)
* [Leaky Wires: Information Leakage and Covert Communication Between FPGA Long Wires](http://www.cs.ox.ac.uk/files/9835/fpga.pdf)
## Cryptoanalysis
### RSA
* [Sliding right into disaster: Left-to-right sliding windows leak](https://eprint.iacr.org/2017/627.pdf)
### DSA
* [Make Sure DSA Signing Exponentiations Really are Constant-Time](http://delivery.acm.org/10.1145/2980000/2978420/p1639-pereida-garcia.pdf)
### ECDSA
* [“Ooh Aah... Just a Little Bit” : A small amount of side channel can go a long way](https://eprint.iacr.org/2014/161.pdf)
* [May the Fourth Be With You: A Microarchitectural Side Channel Attack on Several Real-World Applications of Curve25519](https://obj.umiacs.umd.edu/papers_for_stories/genkin_ACMCCS2017.pdf)
* [Return of the Hidden Number Problem](https://tches.iacr.org/index.php/TCHES/article/download/7337/6509)
### SM2
* [Side-Channel Analysis of SM2: A Late-Stage Featurization Case Study](https://eprint.iacr.org/2018/651.pdf)
### PQC
* [To BLISS-B or not to be - Attacking strongSwan’s Implementation of Post-Quantum Signatures](https://pure.tue.nl/ws/files/92210580/X490.pdf)
* [Flush, Gauss, and Reload – A Cache Attack onthe BLISS Lattice-Based Signature Scheme](https://eprint.iacr.org/2016/300.pdf)
# Defense
## Program Analysis
### Static Analysis
* [Raccoon: Closing Digital Side-Channels through Obfuscated Execution](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-rane.pdf)
* [Verifying Constant-Time Implementations](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_almeida.pdf)
### Dynamic Analysis
* [MicroWalk: A Framework for Finding Side Channels in Binaries](https://dl.acm.org/citation.cfm?id=3274741)
* [DATA – Differential Address Trace Analysis: Finding Address-based Side-Channels in Binaries](https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-weiser.pdf)
## Software
## Cache
* [Strong and Efficient Cache Side-Channel Protection using Hardware Transactional Memory](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-gruss.pdf)
* [CATalyst: Defeating Last-Level Cache Side Channel Attacks in Cloud Computing]((http://ts.data61.csiro.au/publications/nicta_full_text/8984.pdf))
## Hardware
### DRAM
### Cache
* [RIC: Relaxed Inclusion Caches for Mitigating LLC Side-Channel Attacks](http://hodjat.me/pubs/dac17.pdf)


