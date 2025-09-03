/*
MIT License

Copyright (c) 2025 Hugh Davenport

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#ifndef SHA256_H
#define SHA256_H

#define SHA256_H_VERSION_MAJOR 1
#define SHA256_H_VERSION_MINOR 1
#define SHA256_H_VERSION_PATCH 0

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include <stdio.h>
#include <unistd.h>

#include <assert.h>

#define SHA256_DIGEST_BIT_LENGTH 256
#define SHA256_DIGEST_BYTE_LENGTH (SHA256_DIGEST_BIT_LENGTH / 8)
#define SHA256_DIGEST_HEX_LENGTH 2 * SHA256_DIGEST_BYTE_LENGTH

#define SHA256_SNPRINTF_HEX(str, n, hash) do { \
    for (size_t sha256_snprintf_i = 0; sha256_snprintf_i < ((n) / 2 < SHA256_DIGEST_BYTE_LENGTH ? (n) / 2 : SHA256_DIGEST_BYTE_LENGTH); sha256_snprintf_i ++) { \
        snprintf((str) + sha256_snprintf_i * 2, (n) - sha256_snprintf_i * 2, "%02x", (hash)[sha256_snprintf_i]); \
    } \
} while (0)
#define SHA256_DPRINTF_HEX(fd, hash) do { \
    for (size_t sha256_dprintf_i = 0; sha256_dprintf_i < SHA256_DIGEST_BYTE_LENGTH; sha256_dprintf_i ++) { \
        dprintf((fd), "%02x", (hash)[sha256_dprintf_i]); \
    } \
} while (0)
#define SHA256_FPRINTF_HEX(file, hash) do { fflush((file)); SHA256_DPRINTF_HEX(fileno((file)), (hash)); } while (false)
#define SHA256_PRINTF_HEX(hash) do { fflush(stdout); SHA256_DPRINTF_HEX(STDOUT_FILENO, (hash)); } while (false)

bool sha256_digest(const uint8_t *data,
                size_t length,
                uint8_t result[SHA256_DIGEST_BYTE_LENGTH]);

#endif // SHA256_H

#ifdef SHA256_IMPLEMENTATION

#define _SHA256_MAX_LENGTH 18446744073709551614UL // 2^64 - 1
#define _SHA256_BLOCK_SIZE 64
#define _BYTE_MASK 0xFF


// Defined in RFC 6234 Section 3
#define SHA256_ROTR(n, X) (((X) >> (n)) | ((X) << (32-(n))))
#define SHA256_ROTL(n, X) (((X) << (n)) | ((X) >> (32-(n))))

// Defined in RFC 6234 Section 5.1
#define SHA256_CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_BSIG0(x) (SHA256_ROTR(2, (x)) ^ SHA256_ROTR(13, (x)) ^ SHA256_ROTR(22, (x)))
#define SHA256_BSIG1(x) (SHA256_ROTR(6, (x)) ^ SHA256_ROTR(11, (x)) ^ SHA256_ROTR(25, (x)))
#define SHA256_SSIG0(x) (SHA256_ROTR(7, (x)) ^ SHA256_ROTR(18, (x)) ^ ((x) >> 3))
#define SHA256_SSIG1(x) (SHA256_ROTR(17, (x)) ^ SHA256_ROTR(19, (x)) ^ ((x) >> 10))

const uint32_t K[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void _sha256_process_block(uint8_t M[_SHA256_BLOCK_SIZE], uint32_t H[8]) {
    // Defined in RFC 6234 Section 6.2

    // Names from RFC 6234
    //          M is 512 bit block (parameter)
    //          a-h are 8 working variables
    //          H is a 7 word buffer (parameter is last block's H or IVs)
    //          W is a 64 word sequence
    //          TEMP is a buffer
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t W[64];
    uint32_t T1, T2;

    // Step 1. Prepare the message schedule W
    for (int t = 0; t <= 15; t ++) {
        W[t] = ((((uint32_t)M[t*4]) & _BYTE_MASK) << 24) |
            ((((uint32_t)M[t*4 + 1]) & _BYTE_MASK) << 16) |
            ((((uint32_t)M[t*4 + 2]) & _BYTE_MASK) << 8) |
            (((uint32_t)M[t*4 + 3]) & _BYTE_MASK);
    }

    for (int t = 16; t <= 63; t ++) {
        W[t] = SHA256_SSIG1(W[t-2]) + W[t-7] + SHA256_SSIG0(W[t-15]) + W[t-16];
    }

    // Step 2. Initialize the working variables
    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];
    f = H[5];
    g = H[6];
    h = H[7];

    // 3. Perform the main hash computation
    for (int t = 0; t <= 63; t ++) {
        T1 = h + SHA256_BSIG1(e) + SHA256_CH(e, f, g) + K[t] + W[t];
        T2 = SHA256_BSIG0(a) + SHA256_MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    // 4. Compute the intermediate hash value H
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
}

void _sha256_pad_block(uint8_t M[_SHA256_BLOCK_SIZE], uint32_t H[8], uint64_t length) {
    // Defined in RFC 6234 Section 4.1

    assert(length < _SHA256_MAX_LENGTH);
    // a. "1" is appended.
    // b. K "0"s are appended where K is the smallest non-negative solution to the equation
    //    (L + 1 + K) mod 512 = 448
    //
    // Note: As we are operating byte-wise, we add 0x80 for a. and 7 bits of K for b.
    // Here `idx` represents L + 1 + K.
    int idx = length % _SHA256_BLOCK_SIZE;
    M[idx++] = 0x80;

    // There is a possibility that the length of the current block is not enough to hold length of message
    // So finish padding this block, process it, and start a new block.
    if (idx > (_SHA256_BLOCK_SIZE) - 8) {
        while (idx < _SHA256_BLOCK_SIZE) {
            M[idx++] = 0;
        }
        _sha256_process_block(M, H);
        idx = 0;
    }

    while (idx < (_SHA256_BLOCK_SIZE - 8)) {
        M[idx++] = 0;
    }

    // c. Then append the 64-bit block that is L in binary representation.
    length *= 8;
    M[_SHA256_BLOCK_SIZE - 8] = (length >> 56) & _BYTE_MASK;
    M[_SHA256_BLOCK_SIZE - 7] = (length >> 48) & _BYTE_MASK;
    M[_SHA256_BLOCK_SIZE - 6] = (length >> 40) & _BYTE_MASK;
    M[_SHA256_BLOCK_SIZE - 5] = (length >> 32) & _BYTE_MASK;
    M[_SHA256_BLOCK_SIZE - 4] = (length >> 24) & _BYTE_MASK;
    M[_SHA256_BLOCK_SIZE - 3] = (length >> 16) & _BYTE_MASK;
    M[_SHA256_BLOCK_SIZE - 2] = (length >> 8) & _BYTE_MASK;
    M[_SHA256_BLOCK_SIZE - 1] = length & _BYTE_MASK;
}

bool sha256_digest(const uint8_t *data,
                uint64_t length,
                uint8_t result[SHA256_DIGEST_BYTE_LENGTH]) {

    if (length >= _SHA256_MAX_LENGTH) return false;

    // Name and initialisation values from RFC 6234 Section 6.1
    uint32_t H[8] = {
      0x6a09e667,
      0xbb67ae85,
      0x3c6ef372,
      0xa54ff53a,
      0x510e527f,
      0x9b05688c,
      0x1f83d9ab,
      0x5be0cd19
    };

    uint8_t block[_SHA256_BLOCK_SIZE];
    for (size_t idx = 0; idx < length; ) {
        block[idx % _SHA256_BLOCK_SIZE] = data[idx];
        if ((++idx) % _SHA256_BLOCK_SIZE == 0) {
            _sha256_process_block(block, H);
        }
    }

    _sha256_pad_block(block, H, length);
    _sha256_process_block(block, H);

    // After the above computations have been sequentially performed for all
    // of the blocks in the message, the final output is calculated.  For
    // SHA-256, this is the concatenation of all of H(N)0, H(N)1, through
    // H(N)7.

    for (size_t idx = 0; idx < 8; idx ++) {
        result[idx * 4] = (H[idx] >> 24) & _BYTE_MASK;
        result[(idx * 4) + 1] = (H[idx] >> 16) & _BYTE_MASK;
        result[(idx * 4) + 2] = (H[idx] >> 8) & _BYTE_MASK;
        result[(idx * 4) + 3] = H[idx] & _BYTE_MASK;
    }

    return true;
}

#endif // SHA256_IMPLEMENTATION
