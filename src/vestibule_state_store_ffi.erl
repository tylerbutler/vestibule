-module(vestibule_state_store_ffi).

-export([create_table/2, insert/3, take/2, lookup/2, delete_key/2,
         cleanup_expired/1, count/1]).

-define(SERVER, vestibule_state_store_owner).

%% How often the owner sweeps expired entries out of each table. Expired
%% entries are also rejected on read, so this only bounds how long a stale
%% entry occupies memory and a capacity slot.
-define(SWEEP_INTERVAL_MS, 30000).

%% A store handle is {Name, MaxEntries}. Carrying the capacity in the handle
%% lets the owner recreate a table with the right configuration if it has
%% been lost — e.g. after the owner process died and was respawned — so a
%% crash costs the in-flight sessions but not every login until restart.

create_table(Name, MaxEntries) ->
    call({create, Name, MaxEntries}).

insert(Handle, Key, Value) ->
    call({insert, Handle, Key, Value}).

take(Handle, Key) ->
    call({take, Handle, Key}).

lookup(Handle, Key) ->
    call({lookup, Handle, Key}).

delete_key(Handle, Key) ->
    call({delete_key, Handle, Key}).

cleanup_expired(Handle) ->
    call({cleanup_expired, Handle}).

count(Handle) ->
    call({count, Handle}).

call(Request) ->
    case ensure_owner() of
        {ok, Pid} ->
            Ref = make_ref(),
            Monitor = erlang:monitor(process, Pid),
            Pid ! {self(), Ref, Request},
            receive
                {Ref, Reply} ->
                    erlang:demonitor(Monitor, [flush]),
                    Reply;
                {'DOWN', Monitor, process, Pid, _Reason} ->
                    {error, <<"owner_unavailable">>}
            after 5000 ->
                erlang:demonitor(Monitor, [flush]),
                {error, <<"timeout">>}
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
                {ok, Pid}
            catch
                error:badarg ->
                    %% Lost the race to another caller; use its owner.
                    exit(Pid, kill),
                    case whereis(?SERVER) of
                        undefined -> error;
                        Winner -> {ok, Winner}
                    end;
                _:_ ->
                    exit(Pid, kill),
                    error
            end;
        Pid ->
            {ok, Pid}
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
                    case new_table(Name, MaxEntries, Tables) of
                        {ok, Tables2} ->
                            From ! {Ref, {ok, {Name, MaxEntries}}},
                            loop(Tables2);
                        error ->
                            From ! {Ref, {error, <<"table_create_failed">>}},
                            loop(Tables)
                    end
            end;
        {From, Ref, {insert, Handle, Key, Value}} ->
            {Reply, Tables2} = with_table(Handle, Tables, fun(Table, MaxEntries) ->
                insert_bounded(Table, MaxEntries, Key, Value)
            end),
            From ! {Ref, Reply},
            loop(Tables2);
        {From, Ref, {take, Handle, Key}} ->
            {Reply, Tables2} = with_table(Handle, Tables, fun(Table, _) ->
                case ets:take(Table, Key) of
                    [{Key, Value}] -> {ok, Value};
                    [] -> {error, nil}
                end
            end),
            From ! {Ref, Reply},
            loop(Tables2);
        {From, Ref, {lookup, Handle, Key}} ->
            {Reply, Tables2} = with_table(Handle, Tables, fun(Table, _) ->
                case ets:lookup(Table, Key) of
                    [{Key, Value}] -> {ok, Value};
                    [] -> {error, nil}
                end
            end),
            From ! {Ref, Reply},
            loop(Tables2);
        {From, Ref, {delete_key, Handle, Key}} ->
            {Reply, Tables2} = with_table(Handle, Tables, fun(Table, _) ->
                ets:delete(Table, Key),
                {ok, nil}
            end),
            From ! {Ref, Reply},
            loop(Tables2);
        {From, Ref, {cleanup_expired, Handle}} ->
            {Reply, Tables2} = with_table(Handle, Tables, fun(Table, _) ->
                {ok, sweep_expired(Table)}
            end),
            From ! {Ref, Reply},
            loop(Tables2);
        {From, Ref, {count, Handle}} ->
            {Reply, Tables2} = with_table(Handle, Tables, fun(Table, _) ->
                {ok, ets:info(Table, size)}
            end),
            From ! {Ref, Reply},
            loop(Tables2);
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

%% Run Fun against the table a handle names, recreating the table (empty)
%% if this owner does not know it. Returns {Reply, Tables}.
with_table({Name, MaxEntries} = _Handle, Tables, Fun) ->
    case maps:find(Name, Tables) of
        {ok, {Table, Max}} ->
            {run(Fun, Table, Max), Tables};
        error ->
            case new_table(Name, MaxEntries, Tables) of
                {ok, Tables2} ->
                    {ok, {Table, Max}} = maps:find(Name, Tables2),
                    {run(Fun, Table, Max), Tables2};
                error ->
                    {{error, <<"table_create_failed">>}, Tables}
            end
    end;
with_table(_Handle, Tables, _Fun) ->
    {{error, <<"table_not_found">>}, Tables}.

run(Fun, Table, MaxEntries) ->
    try Fun(Table, MaxEntries)
    catch _:_ -> {error, <<"ets_operation_failed">>}
    end.

new_table(Name, MaxEntries, Tables) ->
    try
        Table = ets:new(vestibule_state_store, [set, protected]),
        schedule_sweep(Name),
        {ok, maps:put(Name, {Table, MaxEntries}, Tables)}
    catch
        _:_ -> error
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
