#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "srcmd.h"
#include <base64/base64.h>
#include <cli/cli.h>
#include <msg/msg.h>

const char program[] = "srcmd-keygen";
const int msg_show_pid = 0;

const char cli_help_prefix[] =
"  key-directory defaults to $HOME/.srcmd/key\n";
const char cli_help_suffix[] = "";
const char cli_args_usage[] = "[key-directory]";
const int cli_args_min = 0;
const int cli_args_max = 1;
cli_option cli_options[] = {
  {0,0,0,0,0,0,0}
};

int cli_main(int argc, char* argv[])
{
  nistp224key sec;
  nistp224key pub;
  obuf out;
  str str = {0,0,0};
  const char* home;
  const char* keypath;
  
  uskey_path = "secret";
  upkey_path = "public";
  
  if (argc > 0)
    keypath = argv[0];
  else {
    if ((home = getenv("HOME")) == 0) die1(1, "$HOME is not set.");
    if (chdir(home) != 0)
      die3sys(1, "Could not change directory to '", home, "'");
    mkdir(".srcmd", 0700);
    keypath = ".srcmd/key";
  }
  
  mkdir(keypath, 0755);
  if (chdir(keypath) != 0)
    die3sys(1, "Could not chdir to '", keypath, "'");
  
  random_key(sec);
  nistp224wrap(pub, BASEP224, sec);

  base64_encode_line(sec, sizeof sec, &str);
  if (!obuf_open(&out, uskey_path, OBUF_CREATE|OBUF_EXCLUSIVE, 0400, 0) ||
      !obuf_putstr(&out, &str) ||
      !obuf_putc(&out, '\n') ||
      !obuf_close(&out))
    die3sys(1, "Could not create secret key file '", uskey_path, "'");

  str_truncate(&str, 0);
  base64_encode_line(pub, sizeof pub, &str);
  if (!obuf_open(&out, upkey_path, OBUF_CREATE|OBUF_EXCLUSIVE, 0444, 0) ||
      !obuf_putstr(&out, &str) ||
      !obuf_putc(&out, '\n') ||
      !obuf_close(&out))
    die3sys(1, "Could not create public key file '", upkey_path, "'");
  
  msg3("Your public key is '", str.s, "'");
  
  return 0;
  argc = 1;
}
