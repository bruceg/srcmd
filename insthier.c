#include "conf_bin.c"
#include <installer.h>

void insthier(void) {
  int bin = opendir(conf_bin);
  c(bin, "srcmd",         -1, -1, 0711);
  c(bin, "srcmd-command", -1, -1, 0711);
  c(bin, "srcmd-keygen",  -1, -1, 0711);
  c(bin, "srcmdd",        -1, -1, 0711);
}
