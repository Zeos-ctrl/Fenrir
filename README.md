**Disclaimer: Experimental Cryptography Project**

This cryptography project is an experimental initiative aimed at exploring
innovative cryptographic techniques and methodologies. It is important to note
that this project is not intended for use in production environments or for
securing sensitive information. Users are advised to exercise caution and
discretion when considering the implementation of this experimental
cryptography project.

# Fenrir

Fenrir, is a Cryptographic program designed to test the efficiency and
latency of Identity-Based Cryptography in constrained IOT. The program
implements AES and ASCON-128 encryption as the symmetric ciphers, and
uses Sakai-Ohgishi-Kasahara Identity Based Non-Interactive Key Agreement
in order to exchange keys.

This project uses the following library's:
- <https://github.com/relic-toolkit/relic> 
- <https://github.com/TheMatjaz/LibAscon>

## Compiling

Follow the installation instructions for the two library's above and then run 
**make** in the root directory, this will build the two files **fenrir.out** and 
**test.out** in the root directory. This project also assumes you have **Openssl** 
installed.

## Tests 

Fenrir is designed to test the power efficiency of HIBE (Hierarchical Identity 
Based Encryption), to achieve this it runs the following tests:

1. Parameter Generation - Tests the generation of Public Key (Identity), Secret
value, K1, K2 and Q.
2. Shared Key Generation using SOK and a Hash Function - The test generates a 
partial key for both devices on different levels of a hierarchy, combines them 
and hashes the result to generate a 128-bit key.
3. Message Encryption - Comparing AES-128 and ASCON-128
4. Message Decryption - Comparing AES-128 and ASCON-128
