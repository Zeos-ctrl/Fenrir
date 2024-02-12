#ifndef PARAMS_H
#define PARAMS_H

#define CYPHER 2

/* Ascii art for the banner */
const char asciiArt[] = 
" ________ _______   ________   ________  ___  ________     \n"
"|\\  _____\\\\  ___ \\ |\\   ___  \\|\\   __  \\|\\  \\|\\   __  \\    \n"
"\\ \\  \\__/\\ \\   __/|\\ \\  \\\\ \\  \\ \\  \\|\\  \\ \\  \\ \\  \\|\\  \\   \n"
" \\ \\   __\\\\ \\  \\_|/_\\ \\  \\\\ \\  \\ \\   _  _\\ \\  \\ \\   _  _\\  \n"
"  \\ \\  \\_| \\ \\  \\_|\\ \\ \\  \\\\ \\  \\ \\  \\\\  \\\\ \\  \\ \\  \\\\  \\| \n"
"   \\ \\__\\   \\ \\_______\\ \\__\\\\ \\__\\ \\__\\\\ _\\\\ \\__\\ \\__\\\\ _\\\n"
"    \\|__|    \\|_______|\\|__| \\|__|\\|__|\\|__|\\|__|\\|__|\\|__|";

/* Specifies the cypher type */
typedef enum {
    AES = 1,
    ASCON = 2,
} Cypher;

/* Associated data for ascon */ 
const char associatedData[] = "Associated Data";

#endif // !PARAMS_H
