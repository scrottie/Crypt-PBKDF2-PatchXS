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
    SV* output
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

    sv_setpvn(output, result, 32);
}

SV* _PBKDF2_F( SV* self, SV* hasher, SV* salt, SV* password, SV* iterations, SV* i, SV* initial_hash ) {
    SV* result;  // XS should automatically mark this mortal
    SV* hash;    // XXX mark this mortal
    SV* tmp;
    // hasher is unused; we call Digest::SHA::hmac_256() directly.
    int num_results;

    // fprintf(stderr, "using XS _PBKDF2_F\n");

    int _iterations = SvIV(iterations);

    CV* hmac = get_cv("Digest::SHA::hmac_sha256", 0);

    // dSP; // no longer invoking perl-space methods so don't need the perl arg stack

    // one initial hash using initial_hash and password

    result = newSV(32);

    hmac_sha256( SvPVbyte_nolen(initial_hash), SvCUR(initial_hash), SvPVbyte_nolen(password), SvCUR(password), /* written to */ result );

    hash = sv_2mortal( newSVpvn(SvPVbyte_nolen(result), 32) ); // copy of result, which hmac_sha256() updated

    // 10,000 hashes, feeding hash and password back in to hash each loop, and combining that with the result

    uint64_t * b = (uint64_t *) SvPV_nolen(result);
    uint64_t * a = (uint64_t *) SvPV_nolen(hash);

    for(int iter=2; iter <= _iterations; iter++) {

        hmac_sha256( SvPVbyte_nolen(hash), 32, SvPVbyte_nolen(password), SvCUR(password), /* written to */ hash );

        //     $result ^= $hash;

        b[0] ^= a[0];
        b[1] ^= a[1];
        b[2] ^= a[2];
        b[3] ^= a[3];

    }

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

