# Fenrir

Fenrir, named after the wolf foretold to kill Odin, is a Cryptographic program
designed to test the efficiency and latency of Identity-Based Cryptography in 
constrained IOT. This program is to be tested against PKI solutions to find 
which is best.

## Helpful notes
- The Weil pairing on an elliptic curve is used for identity-based key establishment
and encryption methods (http://www.errthum.com/eric/Works/tatevweil.pdf)

Steps to generate pairings:
1. Initialize relic
2. Generate perameters
3. Choose curve 
4. Compute Tate pairing
5. Store Pairing results
