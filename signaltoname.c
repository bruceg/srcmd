#include <signal.h>

const char* signaltoname(int sig)
{
  switch (sig) {
  case SIGHUP:  return "HUP";
  case SIGINT:  return "INT";
  case SIGQUIT: return "QUIT";
  case SIGILL:  return "ILL";
  case SIGABRT: return "ABRT";
  case SIGFPE:  return "FPE";
  case SIGKILL: return "KILL";
  case SIGSEGV: return "SEGV";
  case SIGPIPE: return "PIPE";
  case SIGALRM: return "ALRM";
  case SIGTERM: return "TERM";
  case SIGUSR1: return "USR1";
  case SIGUSR2: return "USR2";
  case SIGCHLD: return "CHLD";
  case SIGCONT: return "CONT";
  case SIGSTOP: return "STOP";
  case SIGTSTP: return "TSTP";
  case SIGTTIN: return "TTIN";
  case SIGTTOU: return "TTOU";
    // SuSv2 but not POSIX.1: BUS POLL PROF SYS TRAP URG VTALRM XCPU XFSZ
    // Others: IOT EMT STKFLT IO CLD PWR INFO WINCH UNUSED */
  default: return 0;
  }
}
