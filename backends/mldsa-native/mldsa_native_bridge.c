/* Owner-authored ACVP-only bridge; upstream cryptography remains mldsa-native. */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mldsa_native_all.h"

#define MAX_PK MLDSA87_PUBLICKEYBYTES
#define MAX_SK MLDSA87_SECRETKEYBYTES
#define MAX_SIG MLDSA87_BYTES
#define MAX_MESSAGE 8192
#define MAX_CONTEXT 255
#define MAX_INPUT MAX_MESSAGE
#define MAX_HEX_LINE (2 * MAX_INPUT + 3)
#define SEED_BYTES 32
#define RND_BYTES 32
#define MAX_PREFIX (2 + MAX_CONTEXT)

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

/* Only explicit internal seed/rnd APIs are allowed through this bridge. */
int randombytes(uint8_t *output, size_t length);
int randombytes(uint8_t *output, size_t length)
{
  secure_zero(output, length);
  return -1;
}

static int hex_value(char value)
{
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

static int read_hex(uint8_t *output, size_t maximum, size_t *actual, char *line)
{
  size_t index;
  size_t length;
  if (fgets(line, MAX_HEX_LINE, stdin) == NULL) return -1;
  length = strlen(line);
  if (length > 0 && line[length - 1] == '\n') line[--length] = '\0';
  if ((length % 2) != 0 || length / 2 > maximum) return -1;
  *actual = length / 2;
  for (index = 0; index < *actual; index++)
  {
    int high = hex_value(line[index * 2]);
    int low = hex_value(line[index * 2 + 1]);
    if (high < 0 || low < 0) return -1;
    output[index] = (uint8_t)((unsigned int)(high << 4) | (unsigned int)low);
  }
  return 0;
}

static int read_exact(uint8_t *output, size_t expected, char *line)
{
  size_t actual = 0;
  return read_hex(output, expected, &actual, line) == 0 && actual == expected ? 0 : -1;
}

static int print_hex(const char *name, const uint8_t *value, size_t length)
{
  size_t index;
  if (printf("%s=", name) < 0) return -1;
  for (index = 0; index < length; index++)
  {
    if (printf("%02X", value[index]) < 0) return -1;
  }
  return printf("\n") < 0 ? -1 : 0;
}

static int level_sizes(int level, size_t *pk_size, size_t *sk_size, size_t *sig_size)
{
  if (level == 44)
  {
    *pk_size = MLDSA44_PUBLICKEYBYTES;
    *sk_size = MLDSA44_SECRETKEYBYTES;
    *sig_size = MLDSA44_BYTES;
    return 0;
  }
  if (level == 65)
  {
    *pk_size = MLDSA65_PUBLICKEYBYTES;
    *sk_size = MLDSA65_SECRETKEYBYTES;
    *sig_size = MLDSA65_BYTES;
    return 0;
  }
  if (level == 87)
  {
    *pk_size = MLDSA87_PUBLICKEYBYTES;
    *sk_size = MLDSA87_SECRETKEYBYTES;
    *sig_size = MLDSA87_BYTES;
    return 0;
  }
  return -1;
}

static int call_keygen(int level, uint8_t *pk, uint8_t *sk, const uint8_t *seed)
{
  if (level == 44) return mldsa44_keypair_internal(pk, sk, seed);
  if (level == 65) return mldsa65_keypair_internal(pk, sk, seed);
  return mldsa87_keypair_internal(pk, sk, seed);
}

static int call_sign(
    int level, uint8_t *sig, size_t *siglen, const uint8_t *message,
    size_t message_len, const uint8_t *prefix, size_t prefix_len,
    const uint8_t *rnd, const uint8_t *sk)
{
  if (level == 44)
    return mldsa44_signature_internal(sig, siglen, message, message_len,
                                      prefix, prefix_len, rnd, sk, 0);
  if (level == 65)
    return mldsa65_signature_internal(sig, siglen, message, message_len,
                                      prefix, prefix_len, rnd, sk, 0);
  return mldsa87_signature_internal(sig, siglen, message, message_len,
                                    prefix, prefix_len, rnd, sk, 0);
}

static int call_verify(
    int level, const uint8_t *sig, size_t siglen, const uint8_t *message,
    size_t message_len, const uint8_t *context, size_t context_len,
    const uint8_t *pk)
{
  if (level == 44)
    return mldsa44_verify(sig, siglen, message, message_len, context, context_len, pk);
  if (level == 65)
    return mldsa65_verify(sig, siglen, message, message_len, context, context_len, pk);
  return mldsa87_verify(sig, siglen, message, message_len, context, context_len, pk);
}

static int zeroize_self_test(void)
{
  uint8_t probe[64];
  size_t index;
  memset(probe, 0xA5, sizeof(probe));
  secure_zero(probe, sizeof(probe));
  for (index = 0; index < sizeof(probe); index++)
    if (probe[index] != 0) return 1;
  return 0;
}

int main(int argc, char **argv)
{
  uint8_t pk[MAX_PK] = {0};
  uint8_t sk[MAX_SK] = {0};
  uint8_t sig[MAX_SIG] = {0};
  uint8_t message[MAX_MESSAGE] = {0};
  uint8_t context[MAX_CONTEXT] = {0};
  uint8_t seed[SEED_BYTES] = {0};
  uint8_t rnd[RND_BYTES] = {0};
  uint8_t prefix[MAX_PREFIX] = {0};
  char line[MAX_HEX_LINE] = {0};
  size_t pk_size = 0, sk_size = 0, sig_size = 0, sig_len = 0;
  size_t message_len = 0, context_len = 0;
  int level = 0, native_result = -1, status = 2;

  if (argc == 2 && strcmp(argv[1], "--self-test-zeroize") == 0)
    return zeroize_self_test();
  if (argc != 3)
  {
    fputs("bridge requires operation and parameter level\n", stderr);
    goto cleanup;
  }
  level = atoi(argv[2]);
  if (level_sizes(level, &pk_size, &sk_size, &sig_size) != 0)
  {
    fputs("unsupported parameter level\n", stderr);
    goto cleanup;
  }

  if (strcmp(argv[1], "keygen") == 0)
  {
    if (read_exact(seed, sizeof(seed), line) != 0) goto invalid_input;
    native_result = call_keygen(level, pk, sk, seed);
    if (native_result == 0 && print_hex("pk", pk, pk_size) == 0 &&
        print_hex("sk", sk, sk_size) == 0) status = 0;
  }
  else if (strcmp(argv[1], "siggen") == 0)
  {
    if (read_exact(sk, sk_size, line) != 0 ||
        read_hex(message, sizeof(message), &message_len, line) != 0 ||
        read_hex(context, sizeof(context), &context_len, line) != 0 ||
        read_exact(rnd, sizeof(rnd), line) != 0) goto invalid_input;
    if (message_len == 0) goto invalid_input;
    prefix[0] = 0;
    prefix[1] = (uint8_t)context_len;
    memcpy(prefix + 2, context, context_len);
    native_result = call_sign(level, sig, &sig_len, message, message_len,
                              prefix, context_len + 2, rnd, sk);
    if (native_result == 0 && sig_len == sig_size &&
        print_hex("signature", sig, sig_len) == 0) status = 0;
  }
  else if (strcmp(argv[1], "sigver") == 0)
  {
    if (read_exact(pk, pk_size, line) != 0 ||
        read_hex(message, sizeof(message), &message_len, line) != 0 ||
        read_hex(context, sizeof(context), &context_len, line) != 0 ||
        read_exact(sig, sig_size, line) != 0) goto invalid_input;
    if (message_len == 0) goto invalid_input;
    native_result = call_verify(level, sig, sig_size, message, message_len,
                                context, context_len, pk);
    status = printf("testPassed=%d\n", native_result == 0 ? 1 : 0) < 0 ? 2 : 0;
  }
  else
  {
    fputs("unsupported bridge operation\n", stderr);
  }
  goto cleanup;

invalid_input:
  fputs("invalid bridge input\n", stderr);

cleanup:
  secure_zero(pk, sizeof(pk));
  secure_zero(sk, sizeof(sk));
  secure_zero(sig, sizeof(sig));
  secure_zero(message, sizeof(message));
  secure_zero(context, sizeof(context));
  secure_zero(seed, sizeof(seed));
  secure_zero(rnd, sizeof(rnd));
  secure_zero(prefix, sizeof(prefix));
  secure_zero(line, sizeof(line));
  return status;
}
