#include <stdio.h>
#include <stdint.h>

#include "db.h"

//C11 implementation of message-intake protocol

#define CHECKNZ(X) if !((X)) { fwrite("\x01", 1, 1, STDOUT); continue; }

//Protocol: to server: authenticate message, data to commit, end
//To client: \x02 after successful records, \x01 on error, \x00 on termination

int main() {
    uint8_t message_type = 0;
    int message_len = 0;
    char username[8], password[8];
    bool authenticated = false;

    while (message_type != 3) {
        CHECKNZ(fread(&message_type, 1, 1, STDIN));
        CHECKNZ(fread(&message_len, 4, 1, STDIN));
        message_len = ntohl(message_len);

        switch (message_type) {
            case 1: { //auth header
                CHECKNZ(fread(username, 8, 1, STDIN));
                CHECKNZ(fread(password, 8, 1, STDIN));
                if (username[0] || password[0]) {
                    fwrite("\x01", 1, 1, STDOUT);
                    continue;
                }
                if (db.checkpw() || !strcmp(username, "ANON"))
                    authenticated = true;
                else
                    fwrite("\x01", 1, 1, STDOUT);

                break;
            }
            case 2: { //commit data
                if (authenticated) {
                    char message[message_len];
                    CHECKNZ(fread(message, message_len, 1, STDIN));
                    db.commit(username, message, message_len);
                    fwrite("\x02", 1, 1, STDOUT);
                }
                else
                    fwrite("\x01", 1, 1, STDOUT);
                break;
            }
            case 3: { //bye
                fwrite("\x00", 1, 1, STDOUT);
                continue;
            }
        }
    }

    return 0;
}

//bugs: send multiple authentication messages, first one being anon: auth bypass
//
//Shotgun parser: the validity of a transaction is checked alongside program logic
//(the protocol expects an auth header and some data but doesn't limit it to that)
//
//Overloaded field: anon authentication is treated specially
//- Password is don't-care value
//- Username ANON isn't really a username!
//
//Incomplete protocol specification
//- Protocol doesn't appear to specify a maximum length
//  This precludes validation and leaves vulnerable to either
//  user-specified length vulnerability (pictured) or differentials
