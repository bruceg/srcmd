#include <string.h>
#include <unistd.h>
#include <iobuf/iobuf.h>
#include <msg/msg.h>
#include <path/path.h>
#include <str/str.h>

const char program[] = "srcmd-command";
const int msg_show_pid = 0;

static str command;

int main(int argc, char* argv[])
{
  if (argc < 3)
    die3(111, "Usage: ", program, "command-dir program [argument ...]");
  if (argv[2][0] == '/')
    die1(111, "Absolute paths not permitted");
  if (path_contains(argv[2], ".."))
    die1(111, "Command may not contain '..'");
  if (!str_copys(&command, argv[1]) ||
      !path_merge(&command, argv[2]))
    die1(111, "Could not merge command paths");
  argv[2] = command.s;
  execv(command.s, argv+2);
  die3sys(111, "Could not execute '", command.s, "'");
  return 111;
}
