#ifndef CRYPTO__RANDOM__H__
#define CRYPTO__RANDOM__H__

void random_init(long seed);
void random_setstate(char state[256]);
void random_getstate(char state[256]);
void random_bytes(long count, char* out);
unsigned long random_ulong(void);

#endif
