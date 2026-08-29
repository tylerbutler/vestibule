-module(vestibule_state_store_ffi).

-export([create_table/2, insert/3, take/2, lookup/2, delete_key/2,
         cleanup_expired/1, count/1]).

-define(SERVER, vestibule_state_store_owner).

%% How often the owner sweeps expired entries out of each table. Expired
%% entries are also rejected on read, so this only bounds how long a stale
%% entry occupies memory and a capacity slot.
-define(SWEEP_INTERVAL_MS, 30000).

create_table(Name, MaxEntries) ->
    call({create, Name, MaxEntries}).

insert(Table, Key, Value) ->
    call({insert, Table, Key, Value}).

take(Table, Key) ->
    call({take, Table, Key}).

lookup(Table, Key) ->
    call({lookup, Table, Key}).

delete_key(Table, Key) ->
    call({delete_key, Table, Key}).

cleanup_expired(Table) ->
    call({cleanup_expired, Table}).

count(Table) ->
    call({count, Table}).

call(Request) ->
    case ensure_owner() of
        ok ->
            Ref = make_ref(),
            try
                ?SERVER ! {self(), Ref, Request},
                receive
                    {Ref, Reply} -> Reply
                after 5000 ->
                    {error, <<"timeout">>}
                end
            catch
                _:_ ->
                    {error, <<"owner_unavailable">>}
            end;
        error ->
            {error, <<"owner_init_failed">>}
    end.

ensure_owner() ->
    case whereis(?SERVER) of
        undefined ->
            Pid = spawn(fun() -> loop(#{}) end),
            try
                register(?SERVER, Pid),
                ok
            catch
                error:badarg ->
                    exit(Pid, kill),
                    case whereis(?SERVER) of
                        undefined -> error;
                        _ -> ok
                    end;
                _:_ ->
                    exit(Pid, kill),
                    error
            end;
        _ ->
            ok
    end.

%% Tables maps a table name to {EtsTable, MaxEntries}.
loop(Tables) ->
    receive
        {From, Ref, {create, Name, MaxEntries}} ->
            case maps:is_key(Name, Tables) of
                true ->
                    From ! {Ref, {error, <<"table_already_exists">>}},
                    loop(Tables);
                false ->
                    try
                        Table = ets:new(vestibule_state_store,
                                        [set, protected]),
                        schedule_sweep(Name),
                        From ! {Ref, {ok, Name}},
                        loop(maps:put(Name, {Table, MaxEntries}, Tables))
                    catch
                        _:_ ->
                            From ! {Ref, {error, <<"table_create_failed">>}},
                            loop(Tables)
                    end
            end;
        {From, Ref, {insert, Name, Key, Value}} ->
            From ! {Ref, with_table(Name, Tables, fun({Table, MaxEntries}) ->
                insert_bounded(Table, MaxEntries, Key, Value)
            end)},
            loop(Tables);
        {From, Ref, {take, Name, Key}} ->
            From ! {Ref, with_table(Name, Tables, fun({Table, _}) ->
                case ets:take(Table, Key) of
                    [{Key, Value}] -> {ok, Value};
                    [] -> {error, nil}
                end
            end)},
            loop(Tables);
        {From, Ref, {lookup, Name, Key}} ->
            From ! {Ref, with_table(Name, Tables, fun({Table, _}) ->
                case ets:lookup(Table, Key) of
                    [{Key, Value}] -> {ok, Value};
                    [] -> {error, nil}
                end
            end)},
            loop(Tables);
        {From, Ref, {delete_key, Name, Key}} ->
            From ! {Ref, with_table(Name, Tables, fun({Table, _}) ->
                ets:delete(Table, Key),
                {ok, nil}
            end)},
            loop(Tables);
        {From, Ref, {cleanup_expired, Name}} ->
            From ! {Ref, with_table(Name, Tables, fun({Table, _}) ->
                {ok, sweep_expired(Table)}
            end)},
            loop(Tables);
        {From, Ref, {count, Name}} ->
            From ! {Ref, with_table(Name, Tables, fun({Table, _}) ->
                {ok, ets:info(Table, size)}
            end)},
            loop(Tables);
        {sweep, Name} ->
            case maps:find(Name, Tables) of
                {ok, {Table, _}} ->
                    catch sweep_expired(Table),
                    schedule_sweep(Name);
                error ->
                    ok
            end,
            loop(Tables);
        _Unexpected ->
            loop(Tables)
    end.

with_table(Name, Tables, Fun) ->
    case maps:find(Name, Tables) of
        {ok, Entry} ->
            try Fun(Entry)
            catch _:_ -> {error, <<"ets_operation_failed">>}
            end;
        error ->
            {error, <<"table_not_found">>}
    end.

%% Insert unless the table is at capacity. At capacity, expired entries are
%% reclaimed first; only if the table is still full is the insert refused.
%% This keeps the request phase O(1) in the common case while bounding the
%% memory an unauthenticated client can pin by starting flows in a loop.
insert_bounded(Table, MaxEntries, Key, Value) ->
    case ets:info(Table, size) >= MaxEntries of
        true ->
            sweep_expired(Table),
            case ets:info(Table, size) >= MaxEntries of
                true ->
                    {error, <<"store_full">>};
                false ->
                    ets:insert(Table, {Key, Value}),
                    {ok, nil}
            end;
        false ->
            ets:insert(Table, {Key, Value}),
            {ok, nil}
    end.

schedule_sweep(Name) ->
    erlang:send_after(?SWEEP_INTERVAL_MS, self(), {sweep, Name}).

%% Delete every session whose expires_at is at or before now. Runs as a
%% single ets:select_delete (a C-side traversal with no per-row message
%% passing) rather than an Erlang-side fold. Tuples of equal size compare
%% element-wise in Erlang term order, so `=<` on {timestamp, S, Ns} is a
%% correct chronological comparison for the normalised timestamps gleam_time
%% produces (0 =< Ns < 1_000_000_000).
sweep_expired(Table) ->
    Now = now_timestamp(),
    ets:select_delete(Table, [{
        {'_', {session_state, '_', '_', '_', '_', '$1'}},
        [{'=<', '$1', {const, Now}}],
        [true]
    }]).

now_timestamp() ->
    Nanos = erlang:system_time(nanosecond),
    {timestamp, Nanos div 1000000000, Nanos rem 1000000000}.
