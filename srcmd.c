#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <systime.h>
#include <unistd.h>

#include <sysdeps.h>
#include <cli/cli.h>
#include <iobuf/iobuf.h>
#include <msg/msg.h>
#include <net/resolve.h>
#include <net/socket.h>
#include "nistp224/nistp224.h"
#include "rijndael/rijndael.h"
#include "srcmd.h"

const char program[] = "srcmd";
const int msg_show_pid = 0;
int msg_debug_bits = 0;

static const char* home;
static const char* user;
static cli_stringlist* send_envars;
static int send_all_environ = 0;

const char cli_help_prefix[] = "";
const char cli_help_suffix[] = "";
const char cli_args_usage[] = "hostname command [argument ...]";
const int cli_args_min = 2;
const int cli_args_max = -1;
cli_option cli_options[] = {
  { 'd', "debug", CLI_FLAG, 0xff, &msg_debug_bits,
    "Enable debugging output.", 0 },
  { 'E', "allenv", CLI_FLAG, 1, &send_all_environ,
    "Send all environment variables to the server.", 0 },
  { 'e', "env", CLI_STRINGLIST, 0, &send_envars,
    "Send the given environment variable string to the server.", 0 },
  { 'l', "login", CLI_STRING, 0, &user, "Remote username", "$USER" },
  { 'p', "port", CLI_INTEGER, 0, &port, "Port number", "1022" },
  {0,0,0,0,0,0,0}
};

static nistp224key client_pub, client_sec, stored_server_pub;

static ibuf netin;
static obuf netout;

static str strbuf;

static void send_argv(int argc, char** argv)
{
  int i;
  strwrap(str_copys(&strbuf, *argv));
  for (i = 1; i < argc; i++) {
    strwrap(str_catc(&strbuf, 0));
    strwrap(str_cats(&strbuf, argv[i]));
  }
  send_packet(&netout, PACKET_COMMAND, &strbuf);
}

static void send_envvar_split(const char* var, long varlen,
			      const char* val, long vallen)
{
  long len;

  len = varlen + 1 + vallen + 1;
  /* Skip overlong environment strings. */
  if (len >= MAX_PACKET) return;
  /* Send the packet if this string would overfill it. */
  if (strbuf.len + len > MAX_PACKET) {
    send_packet(&netout, PACKET_ENVARS, &strbuf);
    str_truncate(&strbuf, 0);
  }
  strwrap(str_catb(&strbuf, var, varlen) &&
	  str_catc(&strbuf, '=') &&
	  str_catb(&strbuf, val, vallen) &&
	  str_catc(&strbuf, 0));
}

static void send_envvar(const char* var)
{
  const char* val;
  if ((val = strchr(var, '=')) == 0) {
    if ((val = getenv(var)) == 0) return;
    send_envvar_split(var, strlen(var), val, strlen(val));
  }
  else
    send_envvar_split(var, val-var, val+1, strlen(val+1));
}

static void send_endvar(void)
{
  strwrap(str_catc(&strbuf, 0));
  send_packet(&netout, PACKET_ENVARS, &strbuf);
}

static void send_environ(void)
{
  extern char** environ;
  
  str_truncate(&strbuf, 0);
  if (send_all_environ) {
    char** e;
    for (e = environ; *e != 0; ++e)
      send_envvar(*e);
  }
  if (send_envars != 0) {
    cli_stringlist* ev;
    for (ev = send_envars; ev != 0; ev = ev->next)
      send_envvar((char*)ev->string);
  }
  if (strbuf.len > 0)
    send_endvar();
}

static void do_connect(const char* hostname)
{
  int sock1;
  int sock2;
  ipv4addr addr;
  if (!resolve_ipv4name(hostname, &addr))
    die3(1, "Could not determine address for '", hostname, "'");
  if ((sock1 = socket_tcp()) == -1)
    die1sys(1, "Could not create socket.");
  if (!socket_connect4(sock1, &addr, port))
    die3sys(1, "Could not connect to '", hostname, "'");
  if ((sock2 = dup(sock1)) == -1)
    die1sys(1, "Could not duplicate socket.");
  if (!ibuf_init(&netin, sock1, 0, IOBUF_NEEDSCLOSE, 0) ||
      !obuf_init(&netout, sock2, 0, IOBUF_NEEDSCLOSE, 0))
    die1(1, "Setting up I/O buffers failed");
}

static void authenticate(void)
{
  nistp224key ssession_pub;
  nistp224key csession_sec;
  nistp224key csession_pub;
  nistp224key server_pub;
  
  /* Generates one-time secret key Cs */
  random_key(csession_sec);
  /* Calculate and send Cp */
  nistp224wrap(csession_pub, BASEP224, csession_sec);
  strwrap(str_copyb(&strbuf, csession_pub, sizeof csession_pub));
  send_packet(&netout, PACKET_AUTH_CSESSION, &strbuf);

  /* Receive H'p */
  if (recv_packet(&netin, &strbuf, 1) != PACKET_AUTH_SERVER)
    die1(1, "Server did not send authentication data.");
  if (strbuf.len != sizeof server_pub)
    die1(1, "Invalid server key data");
  memcpy(server_pub, strbuf.s, sizeof server_pub);
  str_truncate(&strbuf, 0);
  /* Set authenticator key to HCs = Hp * Cs */
  nistp224wrap(authenticator, server_pub, csession_sec);
  /* Compare H'p to Hp and reject if they're not the same. */
  if (memcmp(server_pub, stored_server_pub, sizeof server_pub) != 0) {
    send_packet(&netout, PACKET_AUTH_FAIL, &strbuf);
    die1(1, "Received server key did not match stored key");
  }
  /* Re-authenticate the last packet with the real authenticator */
  if (!authenticate_packet()) {
    send_packet(&netout, PACKET_AUTH_FAIL, &strbuf);
    die1(1, "Server authentication failed");
  }
  /* Send acceptance packet */
  send_packet(&netout, PACKET_AUTH_SERVOK, &strbuf);
  debug1(DEBUG_AUTH, "Server authentication succeeded");

  /* Start encrypting with hash(HCs) */
  setup_encryption(authenticator);

  /* Client sends Up, Ui */
  strwrap(str_copyb(&strbuf, client_pub, sizeof client_pub));
  strwrap(str_cats(&strbuf, user));
  send_packet(&netout, PACKET_AUTH_CLIENT, &strbuf);
  
  /* Server sends acceptance */
  if (recv_packet(&netin, &strbuf, 0) != PACKET_AUTH_CLIOK)
    die1(1, "Client authentication failed");
  debug1(DEBUG_AUTH, "Client authentication succeeded");

  /* Server sends Sp = BASE * Ss */
  if (recv_packet(&netin, &strbuf, 0) != PACKET_AUTH_SSESSION ||
      strbuf.len != sizeof ssession_pub)
    die1(1, "Did not receive server session key");
  memcpy(ssession_pub, strbuf.s, strbuf.len);
  str_truncate(&strbuf, 0);
  /* Client sends acceptance packet */
  send_packet(&netout, PACKET_AUTH_SESSOK, &strbuf);
  /* Client sets the authenticator key to CSs = Sp * Cs */
  nistp224wrap(authenticator, ssession_pub, csession_sec);
  /* Client starts encrypting with CSs */
  setup_encryption(authenticator);
}

static void load_host_key(const char* hostname)
{
  strwrap(str_copys(&strbuf, hostname));
  str_lower(&strbuf);
  if (chdir(home) == 0 && chdir(lconfdir) == 0 && chdir(hostsdir) == 0)
    if (load_key(strbuf.s, stored_server_pub))
      return;
  if (chdir(gconfdir) == 0 && chdir(hostsdir) == 0)
    if (load_key(strbuf.s, stored_server_pub))
      return;
  die3(1, "Could not load server key for '", strbuf.s, "'");
}

static void load_keys()
{
  nistp224key tmp;
  
  if ((home = getenv("HOME")) == 0) die1(1, "$HOME is not set");
  if (chdir(home) != 0 || chdir(lconfdir) != 0)
    die5sys(1, "Could not change directory to '", home, "/", lconfdir, "'");
  if (user == 0)
    if ((user = getenv("USER")) == 0)
      if ((user = getenv("LOGNAME")) == 0)
	die1(1, "Could not determine username");
  load_key_nofail(uskey_path, client_sec, "client secret key");
  load_key_nofail(upkey_path, client_pub, "client public key");
  nistp224wrap(tmp, BASEP224, client_sec);
  if (memcmp(tmp, client_pub, 28) != 0)
    die1(1, "Invalid client public key");
}

int cli_main(int argc, char* argv[])
{
  signal(SIGPIPE, SIG_IGN);

  config_init();
  load_keys();
  load_host_key(argv[0]);
  
  do_connect(argv[0]);

  authenticate();
  
  send_environ();
  send_argv(argc-1, argv+1);

  multiplex_io(0, 1, &netin, &netout, 1);

  error1("multiplex_io returned");
  return 1;
}
