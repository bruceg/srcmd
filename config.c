#include <stdlib.h>

#include "srcmd.h"

const char* gconfdir = "/etc/srcmd";
const char* lconfdir = ".srcmd";
const char* hostsdir = "hosts";

const char* hpkey_path = "host/public";
const char* hskey_path = "host/secret";

const char* upkey_path = "key/public";
const char* uskey_path = "key/secret";

int port = 1022;

void config_init()
{
  const char* tmp;
  if ((tmp = getenv("SRCMD_GCONFDIR")) != 0) gconfdir = tmp;
  if ((tmp = getenv("SRCMD_LCONFDIR")) != 0) lconfdir = tmp;
  if ((tmp = getenv("SRCMD_HOSTSDIR")) != 0) hostsdir = tmp;
  if ((tmp = getenv("SRCMD_HPKEY")) != 0) hpkey_path = tmp;
  if ((tmp = getenv("SRCMD_HSKEY")) != 0) hskey_path = tmp;
  if ((tmp = getenv("SRCMD_UPKEY")) != 0) upkey_path = tmp;
  if ((tmp = getenv("SRCMD_USKEY")) != 0) uskey_path = tmp;
}
