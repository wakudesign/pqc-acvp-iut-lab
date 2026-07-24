/* Owner-authored ACVP-only bridge; upstream cryptography remains mlkem-native. */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mlkem_native_all.h"

#define MAX_PK MLKEM1024_PUBLICKEYBYTES
#define MAX_SK MLKEM1024_SECRETKEYBYTES
#define MAX_CT MLKEM1024_CIPHERTEXTBYTES
#define MAX_HEX_LINE (2 * MAX_SK + 3)
#define COINS_KEYGEN 64
#define COINS_ENCAPS 32
#define SHARED_SECRET 32

static void secure_zero(void *pointer, size_t length)
{
  volatile uint8_t *bytes = (volatile uint8_t *)pointer;
  while (length > 0)
  {
    *bytes = 0;
    bytes++;
    length--;
  }
}

/* The bridge exposes deterministic APIs only. Satisfy the library's optional
 * randomized API symbol with a fail-closed implementation. */
int randombytes(uint8_t *output, size_t length);
int randombytes(uint8_t *output, size_t length)
{
  secure_zero(output, length);
  return -1;
}

static int hex_value(char value)
{
  if (value >= '0' && value <= '9')
  {
    return value - '0';
  }
  if (value >= 'a' && value <= 'f')
  {
    return value - 'a' + 10;
  }
  if (value >= 'A' && value <= 'F')
  {
    return value - 'A' + 10;
  }
  return -1;
}

static int read_hex(uint8_t *output, size_t expected, char *line)
{
  size_t index;
  size_t length;
  if (fgets(line, MAX_HEX_LINE, stdin) == NULL)
  {
    return -1;
  }
  length = strlen(line);
  if (length > 0 && line[length - 1] == '\n')
  {
    line[--length] = '\0';
  }
  if (length != expected * 2)
  {
    return -1;
  }
  for (index = 0; index < expected; index++)
  {
    int high = hex_value(line[index * 2]);
    int low = hex_value(line[index * 2 + 1]);
    if (high < 0 || low < 0)
    {
      return -1;
    }
    output[index] = (uint8_t)((unsigned int)(high << 4) | (unsigned int)low);
  }
  return 0;
}

static int print_hex(const char *name, const uint8_t *value, size_t length)
{
  size_t index;
  if (printf("%s=", name) < 0)
  {
    return -1;
  }
  for (index = 0; index < length; index++)
  {
    if (printf("%02X", value[index]) < 0)
    {
      return -1;
    }
  }
  return printf("\n") < 0 ? -1 : 0;
}

static int level_sizes(int level, size_t *pk_size, size_t *sk_size, size_t *ct_size)
{
  switch (level)
  {
    case 512:
      *pk_size = MLKEM512_PUBLICKEYBYTES;
      *sk_size = MLKEM512_SECRETKEYBYTES;
      *ct_size = MLKEM512_CIPHERTEXTBYTES;
      return 0;
    case 768:
      *pk_size = MLKEM768_PUBLICKEYBYTES;
      *sk_size = MLKEM768_SECRETKEYBYTES;
      *ct_size = MLKEM768_CIPHERTEXTBYTES;
      return 0;
    case 1024:
      *pk_size = MLKEM1024_PUBLICKEYBYTES;
      *sk_size = MLKEM1024_SECRETKEYBYTES;
      *ct_size = MLKEM1024_CIPHERTEXTBYTES;
      return 0;
    default:
      return -1;
  }
}

static int call_keygen(int level, uint8_t *pk, uint8_t *sk, const uint8_t *coins)
{
  if (level == 512) return mlkem512_keypair_derand(pk, sk, coins);
  if (level == 768) return mlkem768_keypair_derand(pk, sk, coins);
  return mlkem1024_keypair_derand(pk, sk, coins);
}

static int call_encaps(
    int level, uint8_t *ct, uint8_t *ss, const uint8_t *pk,
    const uint8_t *coins)
{
  if (level == 512) return mlkem512_enc_derand(ct, ss, pk, coins);
  if (level == 768) return mlkem768_enc_derand(ct, ss, pk, coins);
  return mlkem1024_enc_derand(ct, ss, pk, coins);
}

static int call_decaps(
    int level, uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
  if (level == 512) return mlkem512_dec(ss, ct, sk);
  if (level == 768) return mlkem768_dec(ss, ct, sk);
  return mlkem1024_dec(ss, ct, sk);
}

static int call_check_pk(int level, const uint8_t *pk)
{
  if (level == 512) return mlkem512_check_pk(pk);
  if (level == 768) return mlkem768_check_pk(pk);
  return mlkem1024_check_pk(pk);
}

static int call_check_sk(int level, const uint8_t *sk)
{
  if (level == 512) return mlkem512_check_sk(sk);
  if (level == 768) return mlkem768_check_sk(sk);
  return mlkem1024_check_sk(sk);
}

static int zeroize_self_test(void)
{
  uint8_t probe[64];
  size_t index;
  memset(probe, 0xA5, sizeof(probe));
  secure_zero(probe, sizeof(probe));
  for (index = 0; index < sizeof(probe); index++)
  {
    if (probe[index] != 0)
    {
      return 1;
    }
  }
  return 0;
}

int main(int argc, char **argv)
{
  uint8_t pk[MAX_PK] = {0};
  uint8_t sk[MAX_SK] = {0};
  uint8_t ct[MAX_CT] = {0};
  uint8_t ss[SHARED_SECRET] = {0};
  uint8_t coins[COINS_KEYGEN] = {0};
  char line_one[MAX_HEX_LINE] = {0};
  char line_two[MAX_HEX_LINE] = {0};
  size_t pk_size = 0;
  size_t sk_size = 0;
  size_t ct_size = 0;
  int level;
  int native_result = -1;
  int status = 2;

  if (argc == 2 && strcmp(argv[1], "--self-test-zeroize") == 0)
  {
    return zeroize_self_test();
  }
  if (argc != 3)
  {
    fputs("bridge requires operation and parameter level\n", stderr);
    goto cleanup;
  }
  level = atoi(argv[2]);
  if (level_sizes(level, &pk_size, &sk_size, &ct_size) != 0)
  {
    fputs("unsupported parameter level\n", stderr);
    goto cleanup;
  }

  if (strcmp(argv[1], "keygen") == 0)
  {
    if (read_hex(coins, 32, line_one) != 0 ||
        read_hex(coins + 32, 32, line_two) != 0)
    {
      fputs("invalid bridge input\n", stderr);
      goto cleanup;
    }
    native_result = call_keygen(level, pk, sk, coins);
    if (native_result == 0 && print_hex("ek", pk, pk_size) == 0 &&
        print_hex("dk", sk, sk_size) == 0)
    {
      status = 0;
    }
  }
  else if (strcmp(argv[1], "encaps") == 0)
  {
    if (read_hex(pk, pk_size, line_one) != 0 ||
        read_hex(coins, COINS_ENCAPS, line_two) != 0)
    {
      fputs("invalid bridge input\n", stderr);
      goto cleanup;
    }
    native_result = call_encaps(level, ct, ss, pk, coins);
    if (native_result == 0 && print_hex("c", ct, ct_size) == 0 &&
        print_hex("k", ss, sizeof(ss)) == 0)
    {
      status = 0;
    }
  }
  else if (strcmp(argv[1], "decaps") == 0)
  {
    if (read_hex(sk, sk_size, line_one) != 0 ||
        read_hex(ct, ct_size, line_two) != 0)
    {
      fputs("invalid bridge input\n", stderr);
      goto cleanup;
    }
    native_result = call_decaps(level, ss, ct, sk);
    if (native_result == 0 && print_hex("k", ss, sizeof(ss)) == 0)
    {
      status = 0;
    }
  }
  else if (strcmp(argv[1], "check-pk") == 0)
  {
    if (read_hex(pk, pk_size, line_one) != 0)
    {
      fputs("invalid bridge input\n", stderr);
      goto cleanup;
    }
    native_result = call_check_pk(level, pk);
    status = printf("valid=%d\n", native_result == 0 ? 1 : 0) < 0 ? 2 : 0;
  }
  else if (strcmp(argv[1], "check-sk") == 0)
  {
    if (read_hex(sk, sk_size, line_one) != 0)
    {
      fputs("invalid bridge input\n", stderr);
      goto cleanup;
    }
    native_result = call_check_sk(level, sk);
    status = printf("valid=%d\n", native_result == 0 ? 1 : 0) < 0 ? 2 : 0;
  }
  else
  {
    fputs("unsupported bridge operation\n", stderr);
  }

  if (status != 0 && native_result != 0)
  {
    fputs("mlkem-native operation failed\n", stderr);
  }

cleanup:
  secure_zero(pk, sizeof(pk));
  secure_zero(sk, sizeof(sk));
  secure_zero(ct, sizeof(ct));
  secure_zero(ss, sizeof(ss));
  secure_zero(coins, sizeof(coins));
  secure_zero(line_one, sizeof(line_one));
  secure_zero(line_two, sizeof(line_two));
  return status;
}

