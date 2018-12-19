# Attack
## CPU
### Last-Level Cache (LLC)
* [FLUSH+RELOAD: a High Resolution, Low Noise, L3 Cache Side-Channel Attack](https://www.usenix.org/system/files/conference/usenixsecurity14/sec14-paper-yarom.pdf)
* [Last-Level Cache Side-Channel Attacks are Practical](http://palms.ee.princeton.edu/system/files/SP_vfinal.pdf)
* [S $ A: A shared cache attack that works across cores and defies VM sandboxing--and its application to AES](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.699.6655&rep=rep1&type=pdf)
* [Prime+Abort: A Timer-Free High-Precision L3 Cache Attack using Intel TSX](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-disselkoen.pdf)
* [Attack Directories, Not Caches: Side-Channel Attacks in a Non-Inclusive World](http://iacoma.cs.uiuc.edu/iacoma-papers/ssp19.pdf)
### Branch Prediction
* [On the Power of Simple Branch Prediction Analysis](http://cryptome.org/sbpa.pdf)
* [Predicting Secret Keys Via Branch Prediction](https://eprint.iacr.org/2006/288.pdf)
* [Jump Over ASLR: Attacking Branch Predictors to Bypass ASLR](http://www.cs.binghamton.edu/~secarch/micro16.pdf)
#### Spectre
* [Spectre Attacks: Exploiting Speculative Execution](https://spectreattack.com/spectre.pdf)
* [ret2spec: Speculative Execution Using Return Stack Buffers](https://christian-rossow.de/publications/ret2spec-ccs2018.pdf)
### Memory Ordering
* [MemJam: A False Dependency Attack against Constant-Time Crypto Implementations](https://arxiv.org/pdf/1711.08002.pdf)
* [Microarchitectural Minefields: 4K-Aliasing Covert Channel and Multi-Tenant Detection in IaaS Cloud](http://jin.ece.ufl.edu/papers/NDSS18.pdf)
### Instruction Cache
* [New Results on Instruction Cache Attacks](https://pdfs.semanticscholar.org/b028/22567d583b89acc0b2bd5afa417ffa835d0a.pdf)
* [Yet another MicroArchitectural Attack:: exploiting I-Cache](http://palms.ee.princeton.edu/system/files/icache_onur07.pdf)
### SGX
* [CacheZoom: How SGX Amplifies the Power of Cache Attacks](https://eprint.iacr.org/2017/618.pdf)
* [Software grand exposure: SGX cache attacks are practical](https://www.usenix.org/system/files/conference/woot17/woot17-paper-brasser.pdf)
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
## ARM
* [ARMageddon: Cache Attacks on Mobile Devices](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_lipp.pdf)
* [AutoLock: Why Cache Attacks on ARM Are Harder Than You Think](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-green.pdf)
## DRAM
* [DRAMA: Exploiting DRAM Addressing for Cross-CPU Attacks](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_pessl.pdf)
### Rowhammer
* [Another Flip in the Wall of Rowhammer Defenses](https://arxiv.org/pdf/1710.00551.pdf)
## GPU
* [Rendered Insecure: GPU Side Channel Attacks are Practical](https://www.cs.ucr.edu/~zhiyunq/pub/ccs18_gpu_side_channel.pdf)
* [Grand Pwning Unit: Accelerating Microarchitectural Attacks with the GPU](https://www.vusec.net/wp-content/uploads/2018/05/glitch.pdf)

# Defense
