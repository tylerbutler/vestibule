-module(vestibule_oidc_test_ffi).

-export([sign/2, reset_counter/0, increment_counter/0, counter/0]).

-include_lib("public_key/include/public_key.hrl").
-include_lib("ywt_core/include/ywt@sign_key_SignRsaSimple.hrl").
-include_lib("ywt_core/include/ywt@sign_key_SignRsaFull.hrl").

sign(Message,
     #sign_rsa_simple{digest_type = DigestType,
                      public_exponent = Exponent,
                      modulus = Modulus,
                      private_exponent = PrivateExponent,
                      padding = Padding}) ->
    sign_rsa(Message,
             DigestType,
             Padding,
             #'RSAPrivateKey'{version = 'two-prime',
                              modulus = Modulus,
                              publicExponent = Exponent,
                              privateExponent = PrivateExponent,
                              otherPrimeInfos = asn1_NOVALUE});
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
                    other_primes_info = OtherPrimes,
                    padding = Padding}) ->
    OtherPrimeInfos =
        case OtherPrimes of
            [] -> asn1_NOVALUE;
            _ ->
                lists:map(
                  fun({Prime, OtherExponent, PrimeCoefficient}) ->
                          #'OtherPrimeInfo'{prime = Prime,
                                            exponent = OtherExponent,
                                            coefficient = PrimeCoefficient}
                  end,
                  OtherPrimes)
        end,
    sign_rsa(Message,
             DigestType,
             Padding,
             #'RSAPrivateKey'{version = 'two-prime',
                              modulus = Modulus,
                              publicExponent = PublicExponent,
                              privateExponent = PrivateExponent,
                              prime1 = FirstPrime,
                              prime2 = SecondPrime,
                              exponent1 = FirstExponent,
                              exponent2 = SecondExponent,
                              coefficient = Coefficient,
                              otherPrimeInfos = OtherPrimeInfos}).

sign_rsa(Message, DigestType, Padding, PrivateKey) ->
    public_key:sign(Message,
                    DigestType,
                    PrivateKey,
                    [{rsa_padding, Padding}]).

reset_counter() ->
    persistent_term:put({?MODULE, counter}, 0),
    nil.

increment_counter() ->
    Value = persistent_term:get({?MODULE, counter}, 0) + 1,
    persistent_term:put({?MODULE, counter}, Value),
    Value.

counter() ->
    persistent_term:get({?MODULE, counter}, 0).
