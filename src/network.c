#include <openssl/ecdsa.h>

enum Domain
{
    INTER,
    INTRA
};
/*
// This function is used to send a message to the other node. It encrypts the 
// message using the symmetric key and sends it to the other node.
// Path: network.c
// Parameters:
//  char *message: The message to be sent 
//  int message_len: The length of the message 
//  struct key_pair *sender: The public, private key pair of the sending node
void send_msg()
{
    return;
}

// This function is used to receive a message from the other node. It decrypts 
// the message using the symmetric key and returns the message. 
// Path: network.c
// Parameters:
//   struct key_pair *receiver: The public key of the receiving node 
void receive_msg()
{
    return;
}

// This function is used to connect to the other node using a websocket and 
// generates a session key to be used for initial communication.
// Path: network.c
// Parameters:
//  none
void connnect_to_device_eccdh()
{
    return;
}
*/
