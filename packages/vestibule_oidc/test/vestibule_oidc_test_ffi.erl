-module(vestibule_oidc_test_ffi).

-export([sign/2,
         reset_counter/0,
         increment_counter/0,
         counter/0,
         concurrent_refresh_claim_count/2,
         sleep/1,
         run_concurrently/2]).

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
    persistent_term:put({?MODULE, counter},
                        atomics:new(1, [{signed, true}])),
    nil.

increment_counter() ->
    atomics:add_get(counter_ref(), 1, 1).

counter() ->
    atomics:get(counter_ref(), 1).

counter_ref() ->
    persistent_term:get({?MODULE, counter}).

sleep(Milliseconds) ->
    timer:sleep(Milliseconds),
    nil.

run_concurrently(Callback, Workers) ->
    Parent = self(),
    Ref = make_ref(),
    Pids = [spawn(fun() ->
                      receive
                          {Ref, go} ->
                              Parent ! {Ref, Callback()}
                      end
                  end)
            || _ <- lists:seq(1, Workers)],
    lists:foreach(fun(Pid) -> Pid ! {Ref, go} end, Pids),
    collect_results(Ref, Workers, []).

collect_results(_Ref, 0, Results) ->
    Results;
collect_results(Ref, Remaining, Results) ->
    receive
        {Ref, Result} ->
            collect_results(Ref, Remaining - 1, [Result | Results])
    end.

concurrent_refresh_claim_count(Key, Workers) ->
    vestibule_oidc_cache_ffi:release_refresh(Key),
    Parent = self(),
    Ref = make_ref(),
    Pids = [spawn(fun() ->
                      receive
                          {Ref, go} ->
                              Claimed =
                                  vestibule_oidc_cache_ffi:claim_refresh(Key, 60),
                              Parent ! {Ref, Claimed},
                              receive
                                  {Ref, stop} -> ok
                              end
                      end
                  end)
            || _ <- lists:seq(1, Workers)],
    lists:foreach(fun(Pid) -> Pid ! {Ref, go} end, Pids),
    Claims = count_claims(Ref, Workers, 0),
    lists:foreach(fun(Pid) -> Pid ! {Ref, stop} end, Pids),
    Claims.

count_claims(_Ref, 0, Claims) ->
    Claims;
count_claims(Ref, Remaining, Claims) ->
    receive
        {Ref, true} ->
            count_claims(Ref, Remaining - 1, Claims + 1);
        {Ref, false} ->
            count_claims(Ref, Remaining - 1, Claims)
    end.
