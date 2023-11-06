#include <relic/relic.h>
#include <openssl/ecdsa.h>

// Struct to store key information
// Path: crypto.c
struct key_pair
{
    char public_key;
    char private_key;
    char shared_value;
    char secret_value;
};

// This function is ran on the Gateway node and gens the public and private keys
// for the requesting node, returning the public key, private key, shared value, and
// secret value. <sPk, Pk, x, Qx>
// Path: crypto.c
// Parameters:
//     int node_id: The ID of the node requesting to join the network
//     int gateway_id: The ID of the gateway node 
void gateway_gen_key_pair(int node_id, int gateway_id)
{
    return;
}


// This function is used to encrypt a message using the symmetric key gend 
// to send to the other node using the PRESENT cipher.
// Path: crypto.c
// Parameters:
//   char *message: The message to be encrypted
//   int message_len: The length of the message 
//   char *key: The symmetric key to encrypt the message with
//   int key_len: The length of the symmetric key 
void encrypt_with_sym_key(char *message, int message_len, char *key, int key_len)
{
    return;
}

// This function is used to decrypt a message using the symmetric key gend 
// using the PRESENT cipher.
// Path: crypto.c
// Parameters:
//  char *message: The message to be decrypted
//  int message_len: The length of the message 
//  char *key: The symmetric key to decrypt the message with
//  int key_len: The length of the symmetric key
void decrypt_with_sym_key(char *message, int message_len, char *key, int key_len)
{
    return;
}

// This function is used to decrypt a message sent from outside the local domain
//
// Received as Ciphertext = <C0, C1, V> the worker can decrypt the message using 
// its secret key as follows:
//
// nodes secret key = gateway secret key + nodes public key * secret element pG,
// where pG is the secret point known only by the gateway and the worker node.
// d = (e(C0, nodes secret key) / e(public perameter Qw, C1))
// m = V XOR H2(d)
// Path: crypto.c
// Parameters:
//   char *message: The message to be decrypted
//   int message_len: The length of the message 
//   struct key_pair *receiver: The public, private key pair of the receiving node 
//   char *pub_key: The public key of the sending node
void dec_cipher_inter(char *message, int message_len, struct key_pair *receiver, char *pub_key)
{
    return;
}

// This function is used to encrypt a message to send to a node outside the local domain
//
// Ciphertext = <rPkr, rPkn, H2(g^r) XOR m>, where 
// r is a random number in the set Zq not including 0, Pkr is the public key of
// the root node, Pkn is the public key of the node receiving the message, H2 is 
// a hash function, g is a generator of the group G1, and m is the message.
// Path: crypto.c
// Parameters:
//  char *message: The message to be encrypted
//  int message_len: The length of the message 
//  struct key_pair *sender: The public, private key pair of the sending node 
//  char *pub_key_receiver: The public key of the receiving node
void enc_cipher_inter(char *message, int message_len, struct key_pair *sender, char *pub_key_receiver)
{
    return;
}

// This function is used to gen the symmetric key using the public key of 
// the receiving node and the public, private key pair of the sending node using 
// bilinear pairing. (SOK key agreement)
// Path: crypto.c
// Parameters:
//   struct key_pair *sender: The public, private key pair of the sending node 
//   char *receiver: The public key of the receiving node 
void sok_gen_sym_key(struct key_pair *sender, char *receiver)
{
    return;
}

// This function is used to gen the two groups of the bilinear pairing, G1 and G2
// using the relic library. The bilinear pairing is defined as follows:
// e: G1 x G1 -> G2
// (Tate pairing)
// Path: crypto.c
// Parameters:
//   none
void gen_pairing_tate()
{
    return;
}

// This function is used to gen the two groups of the bilinear pairing, G1 and G2
// using the relic library. The bilinear pairing is defined as follows:
// e: G1 x G1 -> G2
// (Weil pairing)
// Path: crypto.c
// Parameters:
//   none
void gen_pairing_weil()
{
    return;
}

// This function is used to gen the random secret number s to be used to 
// gen the shared value Qr, where s is the master secret key.
// Path: crypto.c
// Parameters:
//  none
void gen_secret()
{
    return;
}

// This function is used to gen the public perameter Q 
// Path: crypto.c
// Parameters:
//   int secret: The secret value to be used to gen the public perameter
//   char *pub_key: The public key to be used to gen the public perameter
void gen_pub_peram()
{
    return;
}

// This function is used to gen the public key and maps it to the paring G1
// Path: crypto.c
// Parameters:
//  char *node_id: The ID of the node to gen the public key for
void gen_pub_key()
{
    return;
}
