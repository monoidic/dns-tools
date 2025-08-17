/*
   SHA-1 in C
   By Steve Reid <steve@edmweb.com>
   100% Public Domain

   with modifications and additions for OpenCL and NSEC3 by @monoidic
 */

//////////////////////////////// START ME

#define def_memcpy(ident, out_region, in_region)                               \
  void memcpy_##ident(out_region void *dest_x, in_region const void *src_x,    \
                      int n) {                                                 \
    out_region char *dest = (out_region char *)dest_x;                         \
    in_region const char *src = (in_region const char *)src_x;                 \
    for (int i = 0; i < n; i++) {                                              \
      dest[i] = src[i];                                                        \
    }                                                                          \
  }

def_memcpy(glbl_to_priv, __private, __global)

    typedef struct { // 517 bytes
  ushort iterations;
  uchar name_len;
  uchar salt_len;
  char name_buf[255];
  char salt_buf[255];
  uchar indexes[3];
} nsec3_inbuf;

typedef struct { // 20 bytes
  char hash[20];
} nsec3_outbuf;
//////////////////////////////// END ME

typedef struct {
  uint state[5];
  uint count[2];
  char buffer[64];
} SHA1_CTX;

void SHA1Transform(uint *state, const char *buffer);

void SHA1Init(SHA1_CTX *context);

void SHA1Update(SHA1_CTX *context, const char *data, uint len);

void SHA1Final(SHA1_CTX *context);

/*
SHA-1 in C
By Steve Reid <steve@edmweb.com>
100% Public Domain

Test Vectors (from FIPS PUB 180-1)
"abc"
  A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D
"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1
A million repetitions of "a"
  34AA973C D4C4DAA4 F61EEB2B DBAD2731 6534016F
*/

/* #define LITTLE_ENDIAN * This should be #define'd already, if true. */
/* #define SHA1HANDSOFF * Copies data before messing with it. */

// #define SHA1HANDSOFF

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#define blk0_le(i)                                                             \
  (block->l[i] = (rol(block->l[i], 24) & 0xFF00FF00) |                         \
                 (rol(block->l[i], 8) & 0x00FF00FF))
#define blk0_be(i) block->l[i]
#if __ENDIAN_LITTLE__
#define blk0(i) blk0_le(i)
#else
#define blk0(i) blk0_be(i)
#endif

#define blk(i)                                                                 \
  (block->l[i & 15] = rol(block->l[(i + 13) & 15] ^ block->l[(i + 8) & 15] ^   \
                              block->l[(i + 2) & 15] ^ block->l[i & 15],       \
                          1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v, w, x, y, z, i)                                                   \
  z += ((w & (x ^ y)) ^ y) + blk0(i) + 0x5A827999 + rol(v, 5);                 \
  w = rol(w, 30);
#define R1(v, w, x, y, z, i)                                                   \
  z += ((w & (x ^ y)) ^ y) + blk(i) + 0x5A827999 + rol(v, 5);                  \
  w = rol(w, 30);
#define R2(v, w, x, y, z, i)                                                   \
  z += (w ^ x ^ y) + blk(i) + 0x6ED9EBA1 + rol(v, 5);                          \
  w = rol(w, 30);
#define R3(v, w, x, y, z, i)                                                   \
  z += (((w | x) & y) | (w & x)) + blk(i) + 0x8F1BBCDC + rol(v, 5);            \
  w = rol(w, 30);
#define R4(v, w, x, y, z, i)                                                   \
  z += (w ^ x ^ y) + blk(i) + 0xCA62C1D6 + rol(v, 5);                          \
  w = rol(w, 30);

/* Hash a single 512-bit block. This is the core of the algorithm. */

void SHA1Transform(uint *state, const char *buffer) {
  uint a, b, c, d, e;

  typedef union {
    char c[64];
    uint l[16];
  } CHAR64LONG16;

  /* The following had better never be used because it causes the
   * pointer-to-const buffer to be cast into a pointer to non-const.
   * And the result is written through.  I threw a "const" in, hoping
   * this will cause a diagnostic.
   */
  CHAR64LONG16 *block = (CHAR64LONG16 *)buffer;
  /* Copy context->state[] to working vars */
  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];
  /* 4 rounds of 20 operations each. Loop unrolled. */
  R0(a, b, c, d, e, 0);
  R0(e, a, b, c, d, 1);
  R0(d, e, a, b, c, 2);
  R0(c, d, e, a, b, 3);
  R0(b, c, d, e, a, 4);
  R0(a, b, c, d, e, 5);
  R0(e, a, b, c, d, 6);
  R0(d, e, a, b, c, 7);
  R0(c, d, e, a, b, 8);
  R0(b, c, d, e, a, 9);
  R0(a, b, c, d, e, 10);
  R0(e, a, b, c, d, 11);
  R0(d, e, a, b, c, 12);
  R0(c, d, e, a, b, 13);
  R0(b, c, d, e, a, 14);
  R0(a, b, c, d, e, 15);
  R1(e, a, b, c, d, 16);
  R1(d, e, a, b, c, 17);
  R1(c, d, e, a, b, 18);
  R1(b, c, d, e, a, 19);
  R2(a, b, c, d, e, 20);
  R2(e, a, b, c, d, 21);
  R2(d, e, a, b, c, 22);
  R2(c, d, e, a, b, 23);
  R2(b, c, d, e, a, 24);
  R2(a, b, c, d, e, 25);
  R2(e, a, b, c, d, 26);
  R2(d, e, a, b, c, 27);
  R2(c, d, e, a, b, 28);
  R2(b, c, d, e, a, 29);
  R2(a, b, c, d, e, 30);
  R2(e, a, b, c, d, 31);
  R2(d, e, a, b, c, 32);
  R2(c, d, e, a, b, 33);
  R2(b, c, d, e, a, 34);
  R2(a, b, c, d, e, 35);
  R2(e, a, b, c, d, 36);
  R2(d, e, a, b, c, 37);
  R2(c, d, e, a, b, 38);
  R2(b, c, d, e, a, 39);
  R3(a, b, c, d, e, 40);
  R3(e, a, b, c, d, 41);
  R3(d, e, a, b, c, 42);
  R3(c, d, e, a, b, 43);
  R3(b, c, d, e, a, 44);
  R3(a, b, c, d, e, 45);
  R3(e, a, b, c, d, 46);
  R3(d, e, a, b, c, 47);
  R3(c, d, e, a, b, 48);
  R3(b, c, d, e, a, 49);
  R3(a, b, c, d, e, 50);
  R3(e, a, b, c, d, 51);
  R3(d, e, a, b, c, 52);
  R3(c, d, e, a, b, 53);
  R3(b, c, d, e, a, 54);
  R3(a, b, c, d, e, 55);
  R3(e, a, b, c, d, 56);
  R3(d, e, a, b, c, 57);
  R3(c, d, e, a, b, 58);
  R3(b, c, d, e, a, 59);
  R4(a, b, c, d, e, 60);
  R4(e, a, b, c, d, 61);
  R4(d, e, a, b, c, 62);
  R4(c, d, e, a, b, 63);
  R4(b, c, d, e, a, 64);
  R4(a, b, c, d, e, 65);
  R4(e, a, b, c, d, 66);
  R4(d, e, a, b, c, 67);
  R4(c, d, e, a, b, 68);
  R4(b, c, d, e, a, 69);
  R4(a, b, c, d, e, 70);
  R4(e, a, b, c, d, 71);
  R4(d, e, a, b, c, 72);
  R4(c, d, e, a, b, 73);
  R4(b, c, d, e, a, 74);
  R4(a, b, c, d, e, 75);
  R4(e, a, b, c, d, 76);
  R4(d, e, a, b, c, 77);
  R4(c, d, e, a, b, 78);
  R4(b, c, d, e, a, 79);
  /* Add the working vars back into context.state[] */
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
}

/* SHA1Init - Initialize new context */

void SHA1Init(SHA1_CTX *context) {
  /* SHA1 initialization constants */
  context->state[0] = 0x67452301;
  context->state[1] = 0xEFCDAB89;
  context->state[2] = 0x98BADCFE;
  context->state[3] = 0x10325476;
  context->state[4] = 0xC3D2E1F0;
  context->count[0] = context->count[1] = 0;
}

/* Run your data through this. */

void SHA1Update(SHA1_CTX *context, const char *data, uint len) {
  uint i, j;

  j = context->count[0];
  if ((context->count[0] += len << 3) < j) {
    context->count[1]++;
  }
  context->count[1] += (len >> 29);
  j = (j >> 3) & 63;
  if ((j + len) <= 63) {
    i = 0;
  } else {
    i = 64 - j;
    for (int ii = 0; ii < i; ii++) {
      context->buffer[j + ii] = data[ii];
    }
    SHA1Transform(context->state, context->buffer);
    for (; i + 63 < len; i += 64) {
      SHA1Transform(context->state, &data[i]);
    }
    j = 0;
  }

  for (int ii = 0; ii < len - i; ii++) {
    context->buffer[j + ii] = data[i + ii];
  }
}

/* Add padding and return the message digest. */

void SHA1Final(SHA1_CTX *context) {
  unsigned i;

  char finalcount[8];

  char c;

#if 1 /* untested "improvement" by DHR */
  /* Convert context->count to a sequence of bytes
   * in finalcount.  Second element first, but
   * big-endian order within element.
   * But we do it all backwards.
   */
  char *fcp = &finalcount[8];

  for (i = 0; i < 2; i++) {
    uint t = context->count[i];

    int j;

    for (j = 0; j < 4; t >>= 8, j++) {
      *--fcp = (char)t;
    }
  }
#else
  for (i = 0; i < 8; i++) {
    finalcount[i] =
        (char)((context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) &
               255); /* Endian independent */
  }
#endif
  c = 0x80;
  SHA1Update(context, &c, 1);
  while ((context->count[0] & 0x1f8) != 0x1c0) {
    c = 0x00;
    SHA1Update(context, &c, 1);
  }
  SHA1Update(context, finalcount, 8); /* Should cause a SHA1Transform() */
}

#define def_digest(ident, out_region)                                          \
  void SHA1Digest_##ident(SHA1_CTX *context, out_region char *digest) {        \
    for (int i = 0; i < 20; i++) {                                             \
      digest[i] =                                                              \
          (char)((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);       \
    }                                                                          \
  }

def_digest(priv, __private) def_digest(glbl, __global)

    __constant
    char nsec3walkcharset[36] = {'0', '1', '2', '3', '4', '5', '6', '7', '8',
                                 '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                                 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
                                 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};

__kernel void nsec3_main(__global const nsec3_inbuf *inbuffer,
                         __global nsec3_outbuf *outbuffer) {
  SHA1_CTX ctx;
  char namebuf[255], saltbuf[255], hashbuf[20];
  uchar namelen, saltlen;
  ushort iterations;
  uint id, idx;

  const uchar hashlen = 20;

  iterations = inbuffer->iterations;
  namelen = inbuffer->name_len;
  saltlen = inbuffer->salt_len;

  memcpy_glbl_to_priv(namebuf, inbuffer->name_buf, namelen);
  memcpy_glbl_to_priv(saltbuf, inbuffer->salt_buf, saltlen);

  id = get_global_id(0);
  idx = id;

  for (int i = 0; i < sizeof inbuffer->indexes; i++) {
    int char_idx = id % 36;
    id /= 36;
    namebuf[inbuffer->indexes[i]] = nsec3walkcharset[char_idx];
  }

  SHA1Init(&ctx);
  SHA1Update(&ctx, namebuf, namelen);
  SHA1Update(&ctx, saltbuf, saltlen);
  SHA1Final(&ctx);

  if (saltlen) {
    while (iterations--) {
      SHA1Digest_priv(&ctx, hashbuf);
      SHA1Init(&ctx);
      SHA1Update(&ctx, hashbuf, hashlen);
      SHA1Update(&ctx, saltbuf, saltlen);
      SHA1Final(&ctx);
    }
  } else {
    while (iterations--) {
      SHA1Digest_priv(&ctx, hashbuf);
      SHA1Init(&ctx);
      SHA1Update(&ctx, hashbuf, hashlen);
      SHA1Final(&ctx);
    }
  }

  SHA1Digest_glbl(&ctx, outbuffer[idx].hash);
}
