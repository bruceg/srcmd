#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <base64/base64.h>
#include <iobuf/iobuf.h>
#include <msg/msg.h>
#include "srcmd.h"

static str keybuf;
static ibuf in;

int load_key_line(ibuf* in, nistp224key key)
{
  char buf[4096];
  if (!ibuf_gets(in, buf, sizeof buf, '\n')) return 0;
  strwrap(str_truncate(&keybuf, 0));
  if (!base64_decode_line(buf, &keybuf)) return 0;
  if (keybuf.len != sizeof(nistp224key)) return 0;
  memcpy(key, keybuf.s, keybuf.len);
  return 1;
}

int load_key(const char* filename, nistp224key key)
{
  int result;

  if (!ibuf_open(&in, filename, 0)) return 0;
  result = load_key_line(&in, key);
  ibuf_close(&in);
  return result;
}

void load_key_nofail(const char* filename, nistp224key key, const char* name)
{
  if (!load_key(filename, key))
    die2sys(1, "I/O error loading ", name);
}

void random_key(nistp224key key)
{
  int in;
  if ((in = open("/dev/urandom", O_RDONLY)) == -1)
    die1sys(1, "Could not open random device");
  if (read(in, key, sizeof(nistp224key)) != sizeof(nistp224key))
    die1sys(1, "Could not generate random key");
  close(in);
}
