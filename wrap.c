#include "srcmd.h"
#include <msg/msg.h>
#include "nistp224/nistp224.h"

void strwrap(int r)
{
  if (!r) die1(111, "Out of memory");
}

void nistp224wrap(nistp224key xe, nistp224key x, nistp224key e)
{
  if (!nistp224(xe, x, e)) die1(1, "nistp224 failed");
}
