-module(vestibule_oidc_cache_ffi).

-export([get/2,
         put/2,
         claim_refresh/2,
         release_refresh/1,
         complete_refresh/1,
         await_refresh/2]).

-define(TABLE, vestibule_oidc_jwks_cache).
-define(REFRESH_TABLE, vestibule_oidc_jwks_refreshes).
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
    ensure_tables(),
    Now = erlang:monotonic_time(second),
    case ets:lookup(?REFRESH_TABLE, Key) of
        [{Key, InsertedAt, completed, _Owner}]
          when Now - InsertedAt =< CooldownSeconds ->
            false;
        [{Key, _InsertedAt, in_flight, Owner} = Claim] ->
            case is_process_alive(Owner) of
                true ->
                    false;
                false ->
                    ets:delete_object(?REFRESH_TABLE, Claim),
                    insert_refresh_claim(Key, Now)
            end;
        [Expired] ->
            ets:delete_object(?REFRESH_TABLE, Expired),
            insert_refresh_claim(Key, Now);
        [] ->
            insert_refresh_claim(Key, Now)
    end.

insert_refresh_claim(Key, Now) ->
    ets:insert_new(?REFRESH_TABLE, {Key, Now, in_flight, self()}).

release_refresh(Key) ->
    ensure_tables(),
    case ets:lookup(?REFRESH_TABLE, Key) of
        [{Key, _InsertedAt, in_flight, Owner} = Claim]
          when Owner =:= self() ->
            ets:delete_object(?REFRESH_TABLE, Claim);
        _ ->
            ok
    end,
    nil.

complete_refresh(Key) ->
    ensure_tables(),
    case ets:lookup(?REFRESH_TABLE, Key) of
        [{Key, _InsertedAt, in_flight, Owner}] when Owner =:= self() ->
            ets:insert(?REFRESH_TABLE,
                       {Key,
                        erlang:monotonic_time(second),
                        completed,
                        Owner});
        _ ->
            ok
    end,
    nil.

await_refresh(Key, TimeoutMilliseconds) ->
    ensure_tables(),
    Deadline =
        erlang:monotonic_time(millisecond) + max(TimeoutMilliseconds, 0),
    await_refresh_loop(Key, Deadline).

await_refresh_loop(Key, Deadline) ->
    case ets:lookup(?REFRESH_TABLE, Key) of
        [{Key, _InsertedAt, in_flight, Owner} = Claim] ->
            case is_process_alive(Owner) of
                true ->
                    Remaining =
                        Deadline - erlang:monotonic_time(millisecond),
                    case Remaining > 0 of
                        true ->
                            timer:sleep(min(Remaining, 10)),
                            await_refresh_loop(Key, Deadline);
                        false ->
                            nil
                    end;
                false ->
                    ets:delete_object(?REFRESH_TABLE, Claim),
                    nil
            end;
        _ ->
            nil
    end.

ensure_table() ->
    ensure_named_table(?TABLE).

ensure_tables() ->
    ensure_named_table(?TABLE),
    ensure_named_table(?REFRESH_TABLE).

ensure_named_table(Table) ->
    case ets:whereis(Table) of
        undefined ->
            try
                ets:new(Table, [named_table, set, public,
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
