#include <crypto/sha256.h>
#include "srcmd.h"

void hash_key(const nistp224key key, char* hash)
{
  SHA256_ctx sha;
  char tmp[SHA256_DIGEST_LENGTH];
  int i;
  
  SHA256_init(&sha);
  SHA256_update(&sha, key, sizeof *key);
  SHA256_final(&sha);
  SHA256_digest(&sha, tmp);
  for (i = 0; i < HASH_LENGTH; i++)
    hash[i] = tmp[i] ^ tmp[i+HASH_LENGTH];
}
