#ifndef REMOTE_CMD__H__
#define REMOTE_CMD__H__

#include <iobuf/iobuf.h>
#include "rijndael/rijndael.h"
#include <str/str.h>

typedef unsigned char nistp224key[28];
#define BASEP224 ((unsigned char*)"\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n")

#define MAX_PACKET 8192

#define DEBUG_AUTH 0x1
#define DEBUG_EXEC 0x2
#define DEBUG_IO   0x4

typedef enum {
  PACKET_KEEPALIVE = 0,		/* bidirectional */
  PACKET_AUTH_CSESSION = 1,	/* client to server */
  PACKET_AUTH_SERVER = 2,	/* server to client */
  PACKET_AUTH_SERVOK = 3,	/* client to server */
  PACKET_AUTH_CLIENT = 4,	/* client to server */
  PACKET_AUTH_CLIOK = 5,	/* server to client */
  PACKET_AUTH_SSESSION = 6,	/* server to client */
  PACKET_AUTH_SESSOK = 7,	/* client to server */
  PACKET_AUTH_FAIL = 15,	/* bidirectional */
  PACKET_ENVARS = 16,		/* client to server */
  PACKET_COMMAND = 17,		/* client to server */
  PACKET_KILL = 18,		/* client to server */
  PACKET_STDIN = 24,		/* client to server */
  PACKET_STDOUT = 25,		/* server to client */
  PACKET_STDERR = 26,		/* server to client */
  PACKET_EXIT = 32,		/* server to client */
} packet_type;

extern const char* gconfdir;
extern const char* lconfdir;
extern const char* hpkey_path;
extern const char* hskey_path;
extern const char* upkey_path;
extern const char* uskey_path;
extern const char* hostsdir;
extern int port;
extern void config_init();

extern int encrypting;
void encrypt_block(char* ptr, long bytes);
void decrypt_block(char* ptr, long bytes);
void setup_encryption(nistp224key secret);

int load_key(const char* filename, nistp224key key);
void load_key_nofail(const char* filename, nistp224key key, const char* name);
void random_key(nistp224key key);

void multiplex_io(int fdin, int fdout, ibuf* netin, obuf* netout, int client);

extern unsigned long recv_packets;
extern unsigned long recv_packet_bytes;
extern unsigned long recv_plain_bytes;
extern unsigned long sent_packets;
extern unsigned long sent_packet_bytes;
extern unsigned long sent_plain_bytes;
extern nistp224key authenticator;
const char* packet_type_name(packet_type type);
void send_packet(obuf* out, packet_type type, const str* data);
packet_type recv_packet(ibuf* in, str* data, int defer_auth);
int authenticate_packet(void);

void strwrap(int r);
void nistp224wrap(nistp224key xe, nistp224key x, nistp224key e);

#endif
