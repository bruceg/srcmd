#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <systime.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sysdeps.h>
#include <cli/cli.h>
#include <iobuf/iobuf.h>
#include <msg/msg.h>
#include "nistp224/nistp224.h"
#include "rijndael/rijndael.h"
#include "srcmd.h"

const char program[] = "srcmdd";
const int msg_show_pid = 1;
int msg_debug_bits;

const char cli_help_prefix[] = "";
const char cli_help_suffix[] = "";
const char cli_args_usage[] = "command [argument ...]";
const int cli_args_min = 1;
const int cli_args_max = -1;
cli_option cli_options[] = {
  { 'd', "debug", CLI_FLAG,   0xff, &msg_debug_bits,
    "Enable debugging output.", "off" },
  {0,0,0,0,0,0,0}
};

static nistp224key server_pub, server_sec;

static str strbuf;
static str envbuf;

static void exec_command(int argc, char* argv[], const str* command)
{
  char** newargv;
  int i;
  const char* ptr;
  const char* end;
  
  end = command->s + command->len;
  for (i = argc, ptr = command->s; ptr < end; ptr += strlen(ptr)+1)
    ++i;
  if ((newargv = malloc((i+1) * sizeof *newargv)) == 0)
    die1(111, "Out of memory");
  for (i = 0; i < argc; i++)
    newargv[i] = argv[i];
  for (ptr = command->s; ptr < end; ptr += strlen(ptr)+1, ++i)
    newargv[i] = (char*)ptr;
  newargv[i] = 0;
  execvp(newargv[0], newargv);
  die3sys(111, "Could not execute command '", newargv[0], "'");
}

static struct passwd* authenticate(void)
{
  const char* user;
  struct passwd* pw;
  nistp224key csession_pub;
  nistp224key ssession_sec;
  nistp224key ssession_pub;
  nistp224key stored_client_pub;
  nistp224key client_pub;
  
  /* Server receives C'p */
  if (recv_packet(&inbuf, &strbuf, 0) != PACKET_AUTH_CSESSION ||
      strbuf.len != sizeof csession_pub)
    die1(1, "Invalid session public key data");
  memcpy(csession_pub, strbuf.s, strbuf.len);
  /* Server sets the authenticator key to HC's = C'p * Hs */
  nistp224wrap(authenticator, csession_pub, server_sec);
  /* Server sends Hp */
  strwrap(str_copyb(&strbuf, server_pub, sizeof server_pub));
  send_packet(&outbuf, PACKET_AUTH_SERVER, &strbuf);
  /* Client sets authenticator key to HCs */
  /* Client sends acceptance packet */
  if (recv_packet(&inbuf, &strbuf, 0) != PACKET_AUTH_SERVOK)
    die1(1, "Server authentication failed.");

  setup_encryption(authenticator);

  /* Client sends Up, Ui */
  if (recv_packet(&inbuf, &strbuf, 0) != PACKET_AUTH_CLIENT ||
      strbuf.len < sizeof client_pub + 1)
    die1(1, "Invalid client authentication data");
  memcpy(client_pub, strbuf.s, sizeof client_pub);
  user = strbuf.s + sizeof client_pub;
  msg3("Username: '", user, "'");
  /* Server locates stored Up based on system information about Ui */
  pw = getpwnam(user);
  str_truncate(&strbuf, 0);
  if (pw == 0) {
    send_packet(&outbuf, PACKET_AUTH_FAIL, &strbuf);
    die3(1, "Unknown username '", user, "'");
  }
  if (chdir(pw->pw_dir) != 0 || chdir(lconfdir) != 0) {
    send_packet(&outbuf, PACKET_AUTH_FAIL, &strbuf);
    die5sys(1, "Could not change directory to '", pw->pw_dir, "/",
	    lconfdir, "'");
  }
  load_key_nofail("authorized_key", stored_client_pub,
		  "client authorized key");
  /* Compare Up with received U'p */
  if (memcmp(stored_client_pub, client_pub, sizeof client_pub) != 0) {
    send_packet(&outbuf, PACKET_AUTH_FAIL, &strbuf);
    die1(1, "Received and stored client keys don't match");
  }
  /* Server sends acceptance packet */
  send_packet(&outbuf, PACKET_AUTH_CLIOK, &strbuf);
  debug1(DEBUG_AUTH, "Client authentication succeeded");

  /* Server generates one-time secret key Ss */
  random_key(ssession_sec);
  /* Server sends Sp = BASE * Ss */
  nistp224wrap(ssession_pub, BASEP224, ssession_sec);
  strwrap(str_copyb(&strbuf, ssession_pub, sizeof ssession_pub));
  send_packet(&outbuf, PACKET_AUTH_SSESSION, &strbuf);
  /* Client sends acceptance packet */
  if (recv_packet(&inbuf, &strbuf, 0) != PACKET_AUTH_SESSOK)
    die1(1, "Session key setup failed");
  /* Server sets the authenticator key to CSs = Cp * Ss */
  nistp224wrap(authenticator, csession_pub, ssession_sec);
  /* Server start encrypting, using hash(CSs) as the key */
  setup_encryption(authenticator);
  
  return pw;
}

static void load_keys(void)
{
  nistp224key tmp;
  load_key_nofail(hpkey_path, server_pub, "host public key");
  load_key_nofail(hskey_path, server_sec, "host secret key");
  nistp224wrap(tmp, BASEP224, server_sec);
  if (memcmp(tmp, server_pub, 28) != 0)
    die1(1, "Invalid host public key");
}

static void make_environ(void)
{
  char* ptr;
  
  for (ptr = envbuf.s; *ptr != 0; ptr += strlen(ptr) + 1)
    /* Disallow modifications to PATH or LD_* variables */
    if (memcmp(ptr, "PATH=", 5) != 0 &&
	memcmp(ptr, "LD_", 3) != 0)
      if (putenv(ptr) != 0)
	die1(111, "putenv failed");
}

void report_io_bytes(void)
{
  if (str_copys(&strbuf, "in: ") &&
      str_catu(&strbuf, recv_packets) &&
      str_catc(&strbuf, '/') &&
      str_catu(&strbuf, recv_packet_bytes) &&
      str_catc(&strbuf, '/') &&
      str_catu(&strbuf, recv_plain_bytes) &&
      str_cats(&strbuf, " out: ") &&
      str_catu(&strbuf, sent_packets) &&
      str_catc(&strbuf, '/') &&
      str_catu(&strbuf, sent_packet_bytes) &&
      str_catc(&strbuf, '/') &&
      str_catu(&strbuf, sent_plain_bytes))
    msg1(strbuf.s);
}

static pid_t pid = 0;
static void catch_alarm(int ignored)
{
  if (pid > 0)
    kill(pid, SIGTERM);
  else
    die1(1, "Authentication exceded maximum duration");
}

int cli_main(int argc, char* argv[])
{
  struct passwd* pw;
  int pfdin[2];
  int pfdout[2];
  int status;
  packet_type type;
  int maxtime;
  const char* tmp;

  config_init();
  signal(SIGPIPE, SIG_IGN);
  atexit(report_io_bytes);
  if ((tmp = getenv("MAXTIME")) != 0) {
    if ((maxtime = atoi(tmp)) <= 0)
      die2(1, "Invalid $MAXTIME: ", tmp);
    signal(SIGALRM, catch_alarm);
    alarm(maxtime);
  }

  if (pipe(pfdin) != 0 || pipe(pfdout) != 0)
    die1sys(1, "Could not create pipe");
  if (chdir(gconfdir) != 0)
    die3sys(1, "Could not change directory to '", gconfdir, "'");

  load_keys();
  pw = authenticate();
  
  if (setenv("HOME", pw->pw_dir, 1) != 0 ||
      setenv("USER", pw->pw_name, 1) != 0 ||
      setenv("LOGNAME", pw->pw_name, 1) != 0)
    die1(1, "Could not set up environment for command.");
  if (chdir(pw->pw_dir) != 0)
    die3sys(1, "Could not change directory to '", pw->pw_dir, "'");
  if (setgid(pw->pw_gid) != 0) die1sys(1, "Could not set GID");
  if (setuid(pw->pw_uid) != 0) die1sys(1, "Could not set UID");

  strwrap(str_truncate(&envbuf, 0));
  while ((type = recv_packet(&inbuf, &strbuf, 0)) == PACKET_ENVARS)
    strwrap(str_cat(&envbuf, &strbuf));
  if (type != PACKET_COMMAND)
    die1(1, "Invalid packet type from client.");
  make_environ();
  msg3("Command: '", strbuf.s, "'");
  
  switch (pid = fork()) {
  case -1:
    die1sys(111, "fork failed");
  case 0:
    close(0);
    close(1);
    close(2);
    dup2(pfdin[0], 0);
    dup2(pfdout[1], 1);
    dup2(pfdout[1], 2);
    close(pfdin[0]);
    close(pfdin[1]);
    close(pfdout[0]);
    close(pfdout[1]);
    exec_command(argc, argv, &strbuf);
  default:
    close(pfdin[0]);
    close(pfdout[1]);
  }

  multiplex_io(pfdout[0], pfdin[1], &inbuf, &outbuf, 0);
  
  if (waitpid(pid, &status, 0) != pid)
    die1(111, "Failed to catch exit status from command");
  if (WIFEXITED(status))
    status = WEXITSTATUS(status);
  else {
    status = WTERMSIG(status);
    str_truncate(&strbuf, 0);
    str_catu(&strbuf, status);
    error2("Command was killed with signal ", strbuf.s);
    status += 128;
  }
  str_truncate(&strbuf, 0);
  str_catu(&strbuf, status);
  send_packet(&outbuf, PACKET_EXIT, &strbuf);
  
  return 0;
}
