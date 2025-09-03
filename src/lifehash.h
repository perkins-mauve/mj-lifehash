#ifndef LIFEHASH_H
#define LIFEHASH_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// lifehash variations
typedef enum LifeHashVersion {
    lifehash_version1, // hsb gamut; not cmyk-friendly. minor gradient bugs
    lifehash_version2, // cmyk-friendly; original mcnally's and allen's recommendation
    lifehash_detailed, // cmyk-friendly; double resolution
    lifehash_fiducial, // machine-vision fiducials. high-contrast; cmyk-friendly
    lifehash_grayscale_fiducial // machine-vision fiducials. high-contrast; grayscale
} LifeHashVersion;

// raw rgb image returned from provided functions
typedef struct LifeHashImage {
    size_t width;
    size_t height;
    uint8_t* colors;
} LifeHashImage;

// free a lifehash image
void lifehash_image_free(LifeHashImage* image);

// direct quote from original:
// // Make a LifeHash from a UTF-8 string, which may be of any length.
// // The caller is responsible to ensure that the string has undergone any
// // necessary Unicode normalization in order to produce consistent results.
// //
// // The caller is responsible to release the returned image by calling
// // `lifehash_image_free()`.
//
//           s - utf-8 string to be used as seed for image
//     version - specific algorithm to use for generation;
//               see LifeHashVersion above
// module_size - the dimensions of each output pixel
//   has_alpha - whether the output image should include
//               an alpha component
LifeHashImage* lifehash_make_from_utf8(const char* s, LifeHashVersion version, size_t module_size, bool has_alpha);

// direct quote from original:
// // Make a LifeHash from given data, which may be of any size.
// //
// // The caller is responsible to release the returned image by calling
// // `lifehash_image_free()`.
//
//        data - pointer to the beginning of the source data
//               used as seed for image
//         len - total size of source data, in bytes
//     version - specific algorithm to use for generation;
//               see LifeHashVersion above
// module_size - the dimensions of each output pixel
//   has_alpha - whether the output image should include
//               an alpha component
LifeHashImage* lifehash_make_from_data(const uint8_t* data, size_t len, LifeHashVersion version, size_t module_size, bool has_alpha);

// direct quote from original:
// // Make a LifeHash from the SHA256 digest of some other data.
// // The digest must be exactly 32 pseudorandom bytes. This is the base
// // LifeHash creation algorithm, but if you don't already have a SHA256 hash of
// // some data, then you should access it by calling `lifehash_make_from_data()`. If you
// // are starting with a UTF-8 string, call `lifehash_make_from_utf8()`.
// //
// // The caller is responsible to release the returned image by calling
// // `lifehash_image_free()`.
//
//      digest - pointer to the start of the sha256 digest
//               used as the seed for image
//     version - specific algorithm to use for generation;
//               see LifeHashVersion above
// module_size - the dimensions of each output pixel
//   has_alpha - whether the output image should include
//               an alpha component
LifeHashImage* lifehash_make_from_digest(const uint8_t* digest, LifeHashVersion version, size_t module_size, bool has_alpha);

// direct quote from original:
// // Convert the given data to hexadecimal.
// // The caller is responsible to release the returned string by calling `free()`.
//
// data - pointer to the beginning of the source data
//  len - length of source data in bytes
//
// (length of output string is guaranteed to be len * 2)
char* lifehash_data_to_hex(const uint8_t* data, size_t len);

// direct quote from original:
// // Convert the given hexadecimal string to binary data.
// // Returns `true` if successful, and `false` if the string is invalid hexadecimal.
// // When successful, the caller is responsible to release the returned data by calling `free()`.
//
//     utf8 - pointer to the source utf-8 string
// utf8_len - length of source utf-8
//      out - where the pointer to the resulting data should
//            be placed
//  out_len - where the length of the resultind data should
//            be placed
bool lifehash_hex_to_data(const uint8_t* utf8, size_t utf8_len, uint8_t** out, size_t* out_len);

// direct quote from original:
// // Calculates the SHA256 digest of the given data.
//
//   data - pointer to the source data to be digested
//    len - length of source data
// digest - array into which digest should be placed
void lifehash_sha256(const uint8_t* data, size_t len, uint8_t digest[32]);

#ifdef __cplusplus
}
#endif

#endif
