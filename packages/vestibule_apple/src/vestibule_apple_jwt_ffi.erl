-module(vestibule_apple_jwt_ffi).

-export([verify/3, sign_hmac/3]).

-include_lib("public_key/include/public_key.hrl").
-include_lib("ywt_core/include/ywt@verify_key_VerifyEcdsa.hrl").
-include_lib("ywt_core/include/ywt@verify_key_VerifyHmac.hrl").

%% Verify an ECDSA signature (ES256/ES384/ES512).
%% Used for verifying Apple's JWT ID tokens against their JWKS public keys.
verify(Message,
       Signature,
       #verify_ecdsa{curve = Curve,
                     digest_type = DigestType,
                     public_key = PublicKey}) ->
    {RBin, SBin} = split_binary(Signature, byte_size(Signature) div 2),
    R = crypto:bytes_to_integer(RBin),
    S = crypto:bytes_to_integer(SBin),
    DerSignature = public_key:der_encode('ECDSA-Sig-Value',
                                          #'ECDSA-Sig-Value'{r = R, s = S}),
    Params = {#'ECPoint'{point = PublicKey}, {namedCurve, Curve}},
    case catch public_key:verify(Message, DigestType, DerSignature, Params) of
        true -> true;
        _ -> false
    end;

%% Verify an HMAC signature (HS256/HS384/HS512).
%% Used in tests.
verify(Message,
       Signature,
       #verify_hmac{digest_type = DigestType, secret = Secret}) ->
    case catch crypto:hash_equals(
                   crypto:mac(hmac, DigestType, Secret, Message), Signature)
    of
        true -> true;
        _ -> false
    end.

%% Sign with HMAC (for tests only — no EC key generation needed).
sign_hmac(Message, DigestType, Secret) ->
    crypto:mac(hmac, DigestType, Secret, Message).
