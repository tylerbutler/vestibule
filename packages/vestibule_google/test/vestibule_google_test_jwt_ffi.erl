-module(vestibule_google_test_jwt_ffi).

-export([sign/2]).

-include_lib("public_key/include/public_key.hrl").
-include_lib("ywt_core/include/ywt@sign_key_SignRsaFull.hrl").

sign(Message,
     #sign_rsa_full{digest_type = DigestType,
                    public_exponent = PublicExponent,
                    modulus = Modulus,
                    private_exponent = PrivateExponent,
                    first_prime_factor = FirstPrime,
                    second_prime_factor = SecondPrime,
                    first_factor_crt_exponent = FirstExponent,
                    second_factor_crt_exponent = SecondExponent,
                    first_crt_coefficient = Coefficient,
                    padding = Padding}) ->
    Key = #'RSAPrivateKey'{version = 'two-prime',
                           modulus = Modulus,
                           publicExponent = PublicExponent,
                           privateExponent = PrivateExponent,
                           prime1 = FirstPrime,
                           prime2 = SecondPrime,
                           exponent1 = FirstExponent,
                           exponent2 = SecondExponent,
                           coefficient = Coefficient,
                           otherPrimeInfos = asn1_NOVALUE},
    public_key:sign(Message, DigestType, Key, [{rsa_padding, Padding}]).
