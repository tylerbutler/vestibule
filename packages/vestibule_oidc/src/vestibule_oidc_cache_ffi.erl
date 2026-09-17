-module(vestibule_oidc_cache_ffi).

-export([get/2, put/2]).

-define(TABLE, vestibule_oidc_jwks_cache).
-define(MAX_ENTRIES, 64).

get(Key, TtlSeconds) ->
    ensure_table(),
    Now = erlang:monotonic_time(second),
    case ets:lookup(?TABLE, Key) of
        [{Key, InsertedAt, Value}] when Now - InsertedAt =< TtlSeconds ->
            {ok, Value};
        [{Key, InsertedAt, Value}] ->
            ets:delete_object(?TABLE, {Key, InsertedAt, Value}),
            {error, nil};
        [] ->
            {error, nil}
    end.

put(Key, Value) ->
    ensure_table(),
    ets:insert(?TABLE, {Key, erlang:monotonic_time(second), Value}),
    evict_if_needed(),
    nil.

ensure_table() ->
    case ets:whereis(?TABLE) of
        undefined ->
            try
                ets:new(?TABLE, [named_table, set, public,
                                 {heir, whereis(init), nil},
                                 {read_concurrency, true},
                                 {write_concurrency, true}]),
                ok
            catch
                error:badarg -> ok
            end;
        _ ->
            ok
    end.

evict_if_needed() ->
    case ets:info(?TABLE, size) > ?MAX_ENTRIES of
        true ->
            % ponytail: arbitrary eviction; add LRU only if misses matter.
            ets:delete(?TABLE, ets:first(?TABLE));
        false ->
            true
    end.
