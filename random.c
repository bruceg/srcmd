#include <string.h>
#include <crypto/sha256.h>
#include "random.h"

static char pool[256];
static int poolpos = 0;
static char currpool[SHA256_DIGEST_LENGTH];
static int currpos = -1;

static void mix(char* in, char* out)
{
  SHA256_ctx ctx;
  SHA256_init(&ctx);
  SHA256_update(&ctx, in, SHA256_DIGEST_LENGTH);
  SHA256_final(&ctx);
  SHA256_digest(&ctx, out);
}

static void mixin(void)
{
  /* First, mix up from the pool into the temporary pool space */
  mix(pool+poolpos, currpool);
  currpos = 0;
  
  /* Then mix from this temporary pool back into the pool */
  mix(currpool, pool+poolpos);
  poolpos = (poolpos + SHA256_DIGEST_LENGTH) % 256;
}

void random_init(long seed, char* state)
{
  int pos = seed % sizeof pool;
  poolpos = pos - (pos % SHA256_DIGEST_LENGTH);
  mixin();
  currpos = pos % SHA256_DIGEST_LENGTH;
}

void random_setstate(char state[256])
{
  int cp = currpos;
  memcpy(pool, state, sizeof pool);
}

void random_getstate(char state[256])
{
  memcpy(state, pool, sizeof pool);
}

void random_bytes(long count, char* out)
{
  while (count > 0) {
    int bytes;
    if (currpos <= 0 || currpos >= (long)sizeof currpool) mixin();
    bytes = sizeof currpool - currpos;
    if (bytes > count) bytes = count;
    memcpy(out, currpool + currpos, bytes);
    count -= bytes;
    out += bytes;
    currpos += bytes;
  }
}

unsigned long random_ulong(void)
{
  unsigned long tmp;
  random_bytes(sizeof tmp, (char*)&tmp);
  return tmp;
}
