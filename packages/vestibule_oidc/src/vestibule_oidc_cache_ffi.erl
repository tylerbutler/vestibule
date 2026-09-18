-module(vestibule_oidc_cache_ffi).

-export([get/2, put/2, claim_refresh/2, release_refresh/1]).

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

claim_refresh(Key, CooldownSeconds) ->
    ensure_table(),
    RefreshKey = {refresh, Key},
    Now = erlang:monotonic_time(second),
    case ets:lookup(?TABLE, RefreshKey) of
        [{RefreshKey, InsertedAt, true}]
          when Now - InsertedAt =< CooldownSeconds ->
            false;
        [Expired] ->
            ets:delete_object(?TABLE, Expired),
            insert_refresh_claim(RefreshKey, Now);
        [] ->
            insert_refresh_claim(RefreshKey, Now)
    end.

insert_refresh_claim(RefreshKey, Now) ->
    Claimed = ets:insert_new(?TABLE, {RefreshKey, Now, true}),
    evict_if_needed(),
    Claimed.

release_refresh(Key) ->
    ensure_table(),
    ets:delete(?TABLE, {refresh, Key}),
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
