#include <stdlib.h>
#include <string.h>
#include <crypto/sha256.h>
#include <msg/msg.h>
#include "srcmd.h"

#define MAX_PAD (RIJNDAEL_BYTESPERBLOCK-1)
#define CONST_PAD (1+4)
#define AUTH_LENGTH SHA256_DIGEST_LENGTH

static unsigned char buf[MAX_PAD + CONST_PAD + MAX_PACKET + AUTH_LENGTH];
static unsigned padlen;
static unsigned datalen;
static unsigned enclen;

nistp224key authenticator = "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n";

unsigned long recv_packets = 0;
unsigned long recv_packet_bytes = 0;
unsigned long recv_plain_bytes = 0;
unsigned long sent_packets = 0;
unsigned long sent_packet_bytes = 0;
unsigned long sent_plain_bytes = 0;

static void calc_authenticator(char* result)
{
  SHA256_ctx sha;
  char tmp[AUTH_LENGTH];

  /* calculate hash(M) */
  SHA256_init(&sha);
  SHA256_update(&sha, buf, enclen - AUTH_LENGTH);
  SHA256_final(&sha, tmp);

  /* calculate hash(A,hash(M)) */
  SHA256_init(&sha);
  SHA256_update(&sha, authenticator, sizeof authenticator);
  SHA256_update(&sha, tmp, sizeof tmp);
  SHA256_final(&sha, result);
}

int authenticate_packet(void)
{
  char digest[AUTH_LENGTH];
  calc_authenticator(digest);
  return memcmp(digest, buf + enclen - AUTH_LENGTH, AUTH_LENGTH) == 0;
}

const char* packet_type_name(packet_type type)
{
#define T(T,S) case PACKET_##T: return S
  switch (type) {
    T(KEEPALIVE, "keep alive");
    T(AUTH_FAIL, "authentication failure");
    T(AUTH_CSESSION, "client session key");
    T(AUTH_SERVER, "server key");
    T(AUTH_SERVOK, "server authentication success");
    T(AUTH_CLIENT, "client authentication data");
    T(AUTH_CLIOK, "client authentication success");
    T(AUTH_SSESSION, "server session key");
    T(AUTH_SESSOK, "session setup success");
    T(ENVARS, "environment variable(s)");
    T(COMMAND, "command");
    T(STDIN, "command standard input");
    T(STDOUT, "command standard output");
    T(EXIT, "command exit");
  default: return "unknown";
  }
#undef T
}

void send_packet(obuf* out, packet_type type, const str* data)
{
  static uint32 next_packet = 0;
  unsigned i;
  char* ptr;
  const char* typename = packet_type_name(type);
  
  if ((datalen = data->len) > MAX_PACKET)
    die2(1, typename, " packet is too long to send");
  padlen = RIJNDAEL_BYTESPERBLOCK -
    (CONST_PAD + datalen + AUTH_LENGTH) % RIJNDAEL_BYTESPERBLOCK;
  enclen = padlen + CONST_PAD + datalen + AUTH_LENGTH;
  ptr = buf;
  if (encrypting)
    for (i = 0; i < padlen; i++)
      ptr[i] = random() & 0xff;
  else
    memset(ptr, 0, padlen);
  ptr += padlen;
  ptr[0] = (next_packet >> 24) & 0xff;
  ptr[1] = (next_packet >> 16) & 0xff;
  ptr[2] = (next_packet >> 8) & 0xff;
  ptr[3] = next_packet & 0xff;
  ptr[4] = type;
  ptr += CONST_PAD;
  memcpy(ptr, data->s, data->len); ptr += data->len;

  calc_authenticator(ptr);

  if (encrypting)
    encrypt_block(buf, enclen);

  if (!obuf_putc(out, (datalen >> 8) & 0xff) ||
      !obuf_putc(out, datalen & 0xff) ||
      !obuf_write(out, buf, enclen) ||
      !obuf_flush(out))
    die3sys(1, "I/O error sending ", typename, " packet");
  sent_packets++;
  sent_packet_bytes += enclen;
  sent_plain_bytes += data->len;
  debug3(DEBUG_IO, "Sent ", typename, " packet");
}

packet_type recv_packet(ibuf* in, str* data, int defer_auth)
{
  static uint32 next_packet = 0;
  packet_type type;
  unsigned char len_hi;
  unsigned char len_lo;
  uint32 curr_packet;
  const char* packet_name;
  
  if (!ibuf_getc(in, &len_hi) ||
      !ibuf_getc(in, &len_lo))
    die1sys(1, "I/O error receiving packet length");
  datalen = (unsigned)len_hi << 8 | len_lo;
  if (datalen > MAX_PACKET)
    die1(1, "Received oversize packet length");
  padlen = RIJNDAEL_BYTESPERBLOCK -
    (CONST_PAD + datalen + AUTH_LENGTH) % RIJNDAEL_BYTESPERBLOCK;
  enclen = padlen + CONST_PAD + datalen + AUTH_LENGTH;
  if (!ibuf_read(in, buf, enclen))
    die1sys(1, "I/O error while receiving packet");
  if (encrypting)
    decrypt_block(buf, enclen);

  if (!defer_auth)
    if (!authenticate_packet())
      die1(100, "Incorrect authenticator on received packet");
  
  curr_packet = (buf[padlen] << 24) | (buf[padlen+1] << 16) |
    (buf[padlen+2] << 8) | buf[padlen+3];
  type = buf[padlen+4];
  packet_name = packet_type_name(type);
  if (curr_packet != next_packet)
    die3(100, "Received out of sequence ", packet_name, " packet");
  strwrap(str_copyb(data, buf + padlen + CONST_PAD, datalen));
  debug3(DEBUG_IO, "Received ", packet_name, " packet");
  recv_packets++;
  recv_packet_bytes += enclen;
  recv_plain_bytes += datalen;
  return type;
}
