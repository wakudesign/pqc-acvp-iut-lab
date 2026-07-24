/* In-process portable/native comparison harness; not a production RNG API. */
/* SPDX-License-Identifier: Apache-2.0 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "mlkem_native_all.h"

#define MAX_PK MLKEM1024_PUBLICKEYBYTES
#define MAX_SK MLKEM1024_SECRETKEYBYTES
#define MAX_CT MLKEM1024_CIPHERTEXTBYTES
#define SHARED_SECRET 32

static volatile uint8_t benchmark_sink;

int randombytes(uint8_t *output, size_t length);
int randombytes(uint8_t *output, size_t length)
{
  memset(output, 0, length);
  return -1;
}

static uint64_t now_ns(void)
{
  struct timespec value;
#if defined(CLOCK_MONOTONIC_RAW)
  const clockid_t clock_id = CLOCK_MONOTONIC_RAW;
#else
  const clockid_t clock_id = CLOCK_MONOTONIC;
#endif
  if (clock_gettime(clock_id, &value) != 0)
  {
    return 0;
  }
  return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

static long positive_long(const char *text)
{
  char *end = NULL;
  long value;
  errno = 0;
  value = strtol(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || value <= 0)
  {
    return -1;
  }
  return value;
}

static int keygen(int level, uint8_t *pk, uint8_t *sk, const uint8_t *coins)
{
  if (level == 512) return mlkem512_keypair_derand(pk, sk, coins);
  if (level == 768) return mlkem768_keypair_derand(pk, sk, coins);
  return mlkem1024_keypair_derand(pk, sk, coins);
}

static int encaps(
    int level, uint8_t *ct, uint8_t *ss, const uint8_t *pk,
    const uint8_t *coins)
{
  if (level == 512) return mlkem512_enc_derand(ct, ss, pk, coins);
  if (level == 768) return mlkem768_enc_derand(ct, ss, pk, coins);
  return mlkem1024_enc_derand(ct, ss, pk, coins);
}

static int decaps(
    int level, uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
  if (level == 512) return mlkem512_dec(ss, ct, sk);
  if (level == 768) return mlkem768_dec(ss, ct, sk);
  return mlkem1024_dec(ss, ct, sk);
}

static int invoke(
    const char *operation, int level, uint8_t *pk, uint8_t *sk, uint8_t *ct,
    uint8_t *ss, const uint8_t *key_coins, const uint8_t *encaps_coins)
{
  int result;
  if (strcmp(operation, "keyGen") == 0)
  {
    result = keygen(level, pk, sk, key_coins);
    benchmark_sink ^= pk[0];
  }
  else if (strcmp(operation, "encapsulation") == 0)
  {
    result = encaps(level, ct, ss, pk, encaps_coins);
    benchmark_sink ^= ct[0];
  }
  else
  {
    result = decaps(level, ss, ct, sk);
    benchmark_sink ^= ss[0];
  }
  return result;
}

static int measure_operation(
    const char *operation, int level, long batches, long iterations,
    uint8_t *pk, uint8_t *sk, uint8_t *ct, uint8_t *ss,
    const uint8_t *key_coins, const uint8_t *encaps_coins)
{
  long batch;
  long index;
  for (index = 0; index < 20; index++)
  {
    if (invoke(operation, level, pk, sk, ct, ss, key_coins, encaps_coins) != 0)
    {
      return -1;
    }
  }
  for (batch = 0; batch < batches; batch++)
  {
    uint64_t start = now_ns();
    uint64_t finish;
    if (start == 0) return -1;
    for (index = 0; index < iterations; index++)
    {
      if (invoke(operation, level, pk, sk, ct, ss, key_coins, encaps_coins) != 0)
      {
        return -1;
      }
    }
    finish = now_ns();
    if (finish <= start) return -1;
    if (printf(
            "%d,%s,%ld,%ld,%llu,%u\n", level, operation, batch, iterations,
            (unsigned long long)(finish - start),
            (unsigned int)benchmark_sink) < 0)
    {
      return -1;
    }
  }
  return 0;
}

int main(int argc, char **argv)
{
  static const int levels[] = {512, 768, 1024};
  static const char *operations[] = {"keyGen", "encapsulation", "decapsulation"};
  uint8_t pk[MAX_PK] = {0};
  uint8_t sk[MAX_SK] = {0};
  uint8_t ct[MAX_CT] = {0};
  uint8_t ss[SHARED_SECRET] = {0};
  uint8_t key_coins[64];
  uint8_t encaps_coins[32];
  long batches;
  long iterations;
  size_t level_index;
  size_t operation_index;

  if (argc != 3)
  {
    fputs("usage: benchmark BATCHES ITERATIONS\n", stderr);
    return 2;
  }
  batches = positive_long(argv[1]);
  iterations = positive_long(argv[2]);
  if (batches < 0 || iterations < 0)
  {
    fputs("batches and iterations must be positive integers\n", stderr);
    return 2;
  }
  memset(key_coins, 0x11, sizeof(key_coins));
  memset(encaps_coins, 0x22, sizeof(encaps_coins));
  puts("level,operation,batch,iterations,total_ns,checksum");
  for (level_index = 0; level_index < sizeof(levels) / sizeof(levels[0]); level_index++)
  {
    int level = levels[level_index];
    if (keygen(level, pk, sk, key_coins) != 0 ||
        encaps(level, ct, ss, pk, encaps_coins) != 0)
    {
      return 3;
    }
    for (
        operation_index = 0;
        operation_index < sizeof(operations) / sizeof(operations[0]);
        operation_index++)
    {
      if (measure_operation(
              operations[operation_index], level, batches, iterations,
              pk, sk, ct, ss, key_coins, encaps_coins) != 0)
      {
        return 4;
      }
    }
  }
  return 0;
}
