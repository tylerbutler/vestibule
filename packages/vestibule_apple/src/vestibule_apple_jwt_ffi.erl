-module(vestibule_apple_jwt_ffi).

-export([verify/3,
         sign/2,
         sign_es256/2,
         generate_es256_private_key/0,
         verify_es256/3]).

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

sign_es256(Message, Pem) when is_binary(Message), is_binary(Pem) ->
    try
        PrivateKey = decode_es256_private_key(Pem),
        DerSignature = public_key:sign(Message, sha256, PrivateKey),
        {ok, ecdsa_der_to_jose(DerSignature)}
    catch
        _:_ -> {error, nil}
    end.

%% Test support for a round-trip through the same P-256 PEM path used by Apple.
generate_es256_private_key() ->
    PrivateKey = public_key:generate_key({namedCurve, secp256r1}),
    Entry = public_key:pem_entry_encode('PrivateKeyInfo', PrivateKey),
    public_key:pem_encode([Entry]).

verify_es256(Message, Signature, Pem)
  when is_binary(Message), is_binary(Signature), is_binary(Pem) ->
    try
        PrivateKey = decode_es256_private_key(Pem),
        DerSignature = ecdsa_jose_to_der(Signature),
        public_key:verify(Message, sha256, DerSignature, PrivateKey)
    catch
        _:_ -> false
    end.

decode_es256_private_key(Pem) ->
    [Entry] = public_key:pem_decode(Pem),
    PrivateKey = public_key:pem_entry_decode(Entry),
    #'ECPrivateKey'{parameters = {namedCurve, {1, 2, 840, 10045, 3, 1, 7}}} =
        PrivateKey,
    PrivateKey.

ecdsa_der_to_jose(DerSignature) ->
    {'ECDSA-Sig-Value', R, S} =
        public_key:der_decode('ECDSA-Sig-Value', DerSignature),
    <<(fixed_width_integer(R, 32))/binary,
      (fixed_width_integer(S, 32))/binary>>.

ecdsa_jose_to_der(<<R:256/unsigned-big-integer,
                    S:256/unsigned-big-integer>>) ->
    public_key:der_encode('ECDSA-Sig-Value', {'ECDSA-Sig-Value', R, S}).

fixed_width_integer(Integer, Width) ->
    Encoded = binary:encode_unsigned(Integer),
    Padding = Width - byte_size(Encoded),
    <<0:Padding/unit:8, Encoded/binary>>.
