int main(int argc, char *argv[])
{
    return 0;
}

// Initialize the network

// This function is ran on the Gateway node and generates the public and private keys
// for the requesting node, returning the public key, private key, shared value, and
// secret value. <sPk, Pk, x, Qx>
// Path: crypto.c
// Parameters:
//     int node_id: The ID of the node requesting to join the network
//     int gateway_id: The ID of the gateway node 
// Returns:
//   struct key_pair: A struct containing the public key, private key, shared value, and secret value
//   for the requesting node 

// This function is ran on the Worker node and saves the key_pair struct returned by the gateway 
// node securely on the disk.
// Path: network.c
// Parameters:
//    struct key_pair: A struct containing the public key, private key, shared value, and secret value
// Returns:
//   int: 0 if successful, -1 if unsuccessful

// This function is used to encrypt a message using the symmetric key generated 
// to send to the other node. Ciphertext = <rPkr, rPkn, H2(g^r) XOR m>, where 
// r is a random number in the set Zq not including 0, Pkr is the public key of
// the root node, Pkn is the public key of the node receiving the message, H2 is 
// a hash function, g is a generator of the group G1, and m is the message.
// Path: crypto.c
// Parameters:
//   char *message: The message to be encrypted
//   int message_len: The length of the message 
//   char *key: The symmetric key to encrypt the message with
//   int key_len: The length of the symmetric key 
// Returns:
//  char *: The encrypted message 
//  int: The length of the encrypted message

// This function is used to decrypt a message using the symmetric key generated.
// Received as Ciphertext = <C0, C1, V> the worker can decrypt the message using 
// its secret key as follows:
//
// nodes secret key = gateway secret key + nodes public key * secret element pG,
// where pG is the secret point known only by the gateway and the worker node.
// d = (e(C0, nodes secret key) / e(public perameter Qw, C1))
// m = V XOR H2(d)
//
// Path: crypto.c
// Parameters:
//  char *message: The message to be decrypted
//  int message_len: The length of the message 
//  char *key: The symmetric key to decrypt the message with
//  int key_len: The length of the symmetric key
// Returns:
// char *: The decrypted message 
// int: The length of the decrypted message

// This function is used to generate the symmetric key using the public key of 
// the receiving node and the public, private key pair of the sending node using 
// bilinear pairing.
// Path: crypto.c
// Parameters:
//   struct key_pair *sender: The public, private key pair of the sending node 
//   struct key_pair *receiver: The public key of the receiving node 
// Returns:
//  char *: The symmetric key

// This function is used to generate the two groups of the bilinear pairing, G1 and G2.
// e: G1 x G1 -> G2
// Path: crypto.c
// Parameters:
//   none
// Returns:
//   vector_t: A vector containing group G1 
//   vector_t: A vector containing group G2
//   element_t: The bilinear pairing e

// This function is used to generate the random secret number s to be used to 
// generate the shared value Qr, where s is the master secret key.
// Path: crypto.c
// Parameters:
//  none
// Returns:
//  element_t: The random secret number s

// This function picks the secret point P known only by the gateway node and the 
// worker node to generate the public parameter Qw.
// Path: crypto.c

// This function Initializes Hash Function H1 and maps it to G1.
// Path: crypto.c
// Parameters:
//   group_t: The group G1
// Returns:
//   hash_t: The hash function H1

// This function Initializes Hash Function H2 and maps it to G2.
// Path: crypto.c
// Parameters:
//  group_t: The group G2
// Returns:
//  hash_t: The hash function H2

// Struct to hold the perameters of the hash function 
// Path: crypto.c
// Parameters:
//   hash_t: The hash function
//   element_t: The hash function perameter 
//   int: The length of the hash function perameter
