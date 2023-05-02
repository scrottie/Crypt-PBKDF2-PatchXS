#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "src/sha.c"

#ifndef dTHX
        #define pTHX_
        #define aTHX_
#endif

void hmac_sha256(
    UCHR* data, STRLEN datalen,
    UCHR* key, STRLEN keylen,
    UCHR* output
) { 
    int i;
    char *result;
    HMAC hmac;

    if (hmacinit(&hmac, 256, key, (UINT) keylen) == NULL) {
        fprintf(stderr, "hmacinit failed\n");
    }

    hmacwrite(data, (ULNG) datalen << 3, &hmac);
    hmacfinish(&hmac);
    result = (char *) hmacdigest(&hmac);

    memcpy(output, result, (size_t) 32);
}

SV* _PBKDF2_F( SV* self, SV* hasher, SV* salt, SV* password, SV* iterations, SV* i, SV* initial_hash ) {
    int password_len = SvCUR(password);
    UCHR* password_str = (UCHR*) SvPVbyte_nolen(password);
    SV* result;  // XS automatically marks this mortal
    SV* tmp;
    // hasher is unused; we call hmac_256() directly.
    int num_results;
    uint64_t result_str[4];
    uint64_t hash_str[4];

    // fprintf(stderr, "using XS _PBKDF2_F\n");

    int _iterations = SvIV(iterations);

    // dSP; // no longer invoking perl-space methods so don't need the perl arg stack

    // one initial hash using initial_hash and password

    hmac_sha256( SvPVbyte_nolen(initial_hash), SvCUR(initial_hash), password_str, password_len, /* written to */ (UCHR *) &result_str );

    memcpy(hash_str, result_str, 32);

    // 10,000 hashes, feeding hash and password back in to hash each loop, and combining that with the result

    for(int iter=2; iter <= _iterations; iter++) {

        hmac_sha256( (UCHR*)hash_str, 32, password_str, password_len, /* written to */ (UCHR *) &hash_str );

        //     $result ^= $hash;

        result_str[0] ^= hash_str[0];
        result_str[1] ^= hash_str[1];
        result_str[2] ^= hash_str[2];
        result_str[3] ^= hash_str[3];

    }

    result = newSVpvn((UCHR*) result_str, 32);
    return result;

}

MODULE = Crypt::PBKDF2::PatchXS		PACKAGE = Crypt::PBKDF2::PatchXS		

PROTOTYPES: DISABLE


SV *
_PBKDF2_F (self, hasher, salt, password, iterations, i, initial_hash)
        SV *    self
        SV *    hasher
        SV *    salt
        SV *    password
        SV *    iterations
        SV *    i
        SV *    initial_hash
