#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <sysdeps.h>
#include <msg/msg.h>
#include "srcmd.h"

static str strbuf;

static int handle_netin(ibuf* netin, int fdout, const char* out_name,
			int client)
{
  packet_type t;
  t = recv_packet(netin, &strbuf, 0);
  if (client) {
    if (t == PACKET_EXIT)
      exit(atoi(strbuf.s));
    else if (t != PACKET_STDOUT) {
      warn2("Invalid packet type from server, ignoring: ",
	    packet_type_name(t));
      return 1;
    }
  }
  else {
    if (t == PACKET_KILL)
      warn3("Kill signal '", strbuf.s, "' received");
    else if (t != PACKET_STDIN) {
      warn2("Invalid packet type from client, ignoring: ",
	    packet_type_name(t));
      return 1;
    }
  }

  if (strbuf.len == 0) {
    debug1(DEBUG_IO, "(last packet marked EOF)");
    close(fdout);
    return 0;
  }
  else if (fdout != -1) {
    const char* ptr = strbuf.s;
    long len = strbuf.len;
    while (len > 0) {
      long wr = write(fdout, ptr, len);
      if (wr == -1) {
	if (errno == EPIPE) {
	  fdout = -1;
	  break;
	}
	else
	  die2sys(1, "I/O error writing to ", out_name);
      }
      len -= wr;
      ptr += wr;
    }
  }
  return 1;
}

static void cleario(iopoll_fd* io)
{
  io->fd = -1;
  io->events = 0;
  io->revents = 0;
}

void multiplex_io(int fdin, int fdout, ibuf* netin, obuf* netout, int client)
{
  iopoll_fd io[2];
  const char* fd_in_name;
  const char* fd_out_name;
  int packet_type;
  
  io[0].fd = fdin;
  io[0].events = IOPOLL_READ;
  io[1].fd = netin->io.fd;
  io[1].events = IOPOLL_READ;

  strwrap(str_truncate(&strbuf, MAX_PACKET));
  if (client) {
    fd_in_name = "standard input";
    fd_out_name = "standard output";
    packet_type = PACKET_STDIN;
  }
  else {
    fd_in_name = fd_out_name = "command pipe";
    packet_type = PACKET_STDOUT;
  }
  
  for (;;) {
    /* Handle any pending input packet data */
    while (netin->io.bufstart < netin->io.buflen)
      if (!handle_netin(netin, fdout, fd_out_name, client))
	cleario(&io[1]);

    if (iopoll(io, 2, -1) == -1) {
      if (errno == EINTR || errno == EAGAIN) continue;
      else die1sys(1, "poll failed");
    }
    if (io[0].revents != 0) {
      long rd = read(fdin, strbuf.s, MAX_PACKET);
      if (rd == -1) die2sys(1, "I/O error reading from ", fd_in_name);
      if (rd == 0) {
	if (!client) return;
	cleario(&io[0]);
      }
      strbuf.len = rd;
      send_packet(netout, packet_type, &strbuf);
    }
    if (io[1].revents != 0)
      if (!handle_netin(netin, fdout, fd_out_name, client))
	cleario(&io[1]);
  }
}
