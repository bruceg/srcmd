#include <crypto/sha256.h>
#include <msg/msg.h>
#include "srcmd.h"

int encrypting = 0;
static rijndael_cipher drc;
static rijndael_cipher erc;

void encrypt_block(char* ptr, long bytes)
{
  if (encrypting) {
    if (rijndael_encrypt_blocks(&erc, ptr, bytes, ptr) != bytes)
      die1(1, "Internal error: Encryption failed");
  }
}
  
void decrypt_block(char* ptr, long bytes)
{
  if (encrypting) {
    if (rijndael_decrypt_blocks(&drc, ptr, bytes, ptr) != bytes)
      die1(1, "Internal error: Decryption failed");
  }
}

void setup_encryption(nistp224key secret)
{
  int i;
  SHA256_ctx sha;
  char key[16];
  char digest[SHA256_DIGEST_LENGTH];
  
  SHA256_init(&sha);
  SHA256_update(&sha, secret, sizeof *secret);
  SHA256_final(&sha, digest);
  for (i = 0; i < 16; i++)
    key[i] = digest[i] ^ digest[i+16];
  
  rijndael_init(&drc, RIJNDAEL_DECRYPT, sizeof key, key, RIJNDAEL_CBC, 0);
  rijndael_init(&erc, RIJNDAEL_ENCRYPT, sizeof key, key, RIJNDAEL_CBC, 0);
  encrypting = 1;
}
