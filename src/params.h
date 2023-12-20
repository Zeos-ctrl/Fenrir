#ifndef PARAMS_H
#define PARAMS_H

#define GATEWAY_IP "192.168.1.126"
#define GATEWAY_PORT 8081
#define ROOT_PORT 8080
#define PACKET_SIZE 1024
#define DEVICE_TYPE 2
#define CYPHER 1

/* Ascii art for the banner */
const char asciiArt[] = 
" ________ _______   ________   ________  ___  ________     \n"
"|\\  _____\\\\  ___ \\ |\\   ___  \\|\\   __  \\|\\  \\|\\   __  \\    \n"
"\\ \\  \\__/\\ \\   __/|\\ \\  \\\\ \\  \\ \\  \\|\\  \\ \\  \\ \\  \\|\\  \\   \n"
" \\ \\   __\\\\ \\  \\_|/_\\ \\  \\\\ \\  \\ \\   _  _\\ \\  \\ \\   _  _\\  \n"
"  \\ \\  \\_| \\ \\  \\_|\\ \\ \\  \\\\ \\  \\ \\  \\\\  \\\\ \\  \\ \\  \\\\  \\| \n"
"   \\ \\__\\   \\ \\_______\\ \\__\\\\ \\__\\ \\__\\\\ _\\\\ \\__\\ \\__\\\\ _\\\n"
"    \\|__|    \\|_______|\\|__| \\|__|\\|__|\\|__|\\|__|\\|__|\\|__|";

/* Specifies the device type */
typedef enum {
    ROOT = 1,
    GATEWAY = 2,
    NODE = 3,
} DeviceType;

/* Specifies the cypher type */
typedef enum {
    AES = 1,
    ASCON = 2,
} Cypher;

#endif // !PARAMS_H
