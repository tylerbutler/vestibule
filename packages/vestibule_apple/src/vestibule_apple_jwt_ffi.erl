-module(vestibule_apple_jwt_ffi).

-export([verify/3, sign/2]).

-include_lib("public_key/include/public_key.hrl").
-include_lib("ywt_core/include/ywt@verify_key_VerifyRsa.hrl").
-include_lib("ywt_core/include/ywt@sign_key_SignRsaSimple.hrl").
-include_lib("ywt_core/include/ywt@sign_key_SignRsaFull.hrl").

%% Apple ID tokens are exclusively RS256. Keep the accepted key shape and
%% algorithm narrow so callers cannot substitute an HMAC or ECDSA key.
verify(Message,
       Signature,
       #verify_rsa{digest_type = sha256,
                   exponent = Exponent,
                   modulus = Modulus,
                   padding = rsa_pkcs1_padding})
  when is_binary(Message),
       is_binary(Signature),
       is_integer(Exponent),
       Exponent > 1,
       is_integer(Modulus),
       Modulus > 0 ->
    PublicKey = #'RSAPublicKey'{modulus = Modulus,
                                publicExponent = Exponent},
    try
        public_key:verify(Message,
                          sha256,
                          Signature,
                          PublicKey,
                          [{rsa_padding, rsa_pkcs1_padding}])
    catch
        _:_ -> false
    end;
verify(_Message, _Signature, _Key) ->
    false.

%% Test support for producing realistic RSA JWT fixtures. Production code only
%% calls verify/3.
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
