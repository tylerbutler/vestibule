-module(vestibule_oidc_jwt_ffi).

-export([make_rsa_key/3, verify/3]).

-include_lib("public_key/include/public_key.hrl").
-include_lib("ywt_core/include/ywt@verify_key_VerifyRsa.hrl").

make_rsa_key(KeyId, ModulusEncoded, ExponentEncoded)
  when is_binary(ModulusEncoded), is_binary(ExponentEncoded) ->
    try
        ModulusBytes = base64url_decode(ModulusEncoded),
        ExponentBytes = base64url_decode(ExponentEncoded),
        ModulusBits = bit_size(ModulusBytes),
        Exponent = binary:decode_unsigned(ExponentBytes),
        Modulus = binary:decode_unsigned(ModulusBytes),
        case byte_size(ModulusBytes) > 0
             andalso binary:first(ModulusBytes) band 16#80 =/= 0
             andalso byte_size(ExponentBytes) > 0
             andalso binary:first(ExponentBytes) =/= 0
             andalso ModulusBits >= 2048 andalso ModulusBits =< 8192
             andalso Exponent >= 3 andalso Exponent =< 16#FFFFFFFF
             andalso Exponent rem 2 =:= 1 of
            true ->
                {ok, #verify_rsa{id = KeyId,
                                 digest_type = sha256,
                                 exponent = Exponent,
                                 modulus = Modulus,
                                 padding = rsa_pkcs1_padding}};
            false ->
                {error, nil}
        end
    catch
        _:_ -> {error, nil}
    end;
make_rsa_key(_KeyId, _ModulusEncoded, _ExponentEncoded) ->
    {error, nil}.

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

base64url_decode(Value) ->
    Padding = case byte_size(Value) rem 4 of
                  0 -> <<>>;
                  2 -> <<"==">>;
                  3 -> <<"=">>;
                  _ -> erlang:error(invalid_base64url)
              end,
    Standard0 = binary:replace(Value, <<"-">>, <<"+">>, [global]),
    Standard = binary:replace(Standard0, <<"_">>, <<"/">>, [global]),
    base64:decode(<<Standard/binary, Padding/binary>>).
