-module(vestibule_state_store_ffi).

-export([create_table/3, insert/4, take/2, take_for_provider/3,
         take_for_provider_at/4, lookup/2, delete_key/2, cleanup_expired/1,
         count/1, monotonic_seconds/0]).

-define(SERVER, vestibule_state_store_owner).

%% How often the owner sweeps expired entries out of each table. Expired
%% entries are also rejected on read, so this only bounds how long a stale
%% entry occupies memory and a capacity slot.
-define(SWEEP_INTERVAL_MS, 30000).
-define(CALL_TIMEOUT_MS, 5000).

%% A store handle is {Name, MaxEntries, MaxEntriesPerClient}. Carrying the limits
%% lets the owner recreate a table with the right configuration if it has
%% been lost — e.g. after the owner process died and was respawned — so a
%% crash costs the in-flight sessions but not every login until restart.

create_table(Name, MaxEntries, MaxEntriesPerClient) ->
    call({create, Name, MaxEntries, MaxEntriesPerClient}).

insert(Handle, Key, ClientKey, Value) ->
    Deadline = erlang:monotonic_time(millisecond) + ?CALL_TIMEOUT_MS,
    call_insert({insert, Handle, Key, ClientKey, Value, Deadline}, Deadline).

take(Handle, Key) ->
    call({take, Handle, Key}).

take_for_provider(Handle, Key, Provider) ->
    call({take_for_provider, Handle, Key, Provider}).

take_for_provider_at(Handle, Key, Provider, Now) ->
    call({take_for_provider, Handle, Key, Provider, Now}).

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
            after ?CALL_TIMEOUT_MS ->
                erlang:demonitor(Monitor, [flush]),
                {error, <<"timeout">>}
            end;
        error ->
            {error, <<"owner_init_failed">>}
    end.

call_insert(Request, Deadline) ->
    case ensure_owner() of
        {ok, Pid} ->
            Ref = make_ref(),
            Monitor = erlang:monitor(process, Pid),
            Pid ! {self(), Ref, Request},
            await_insert_provisional(Pid, Ref, Monitor, Deadline);
        error ->
            {error, <<"owner_init_failed">>}
    end.

await_insert_provisional(Pid, Ref, Monitor, Deadline) ->
    receive
        {Ref, insert_provisional} ->
            Pid ! {self(), Ref, insert_ack},
            await_insert_confirmation(Pid, Ref, Monitor);
        {Ref, Reply} ->
            erlang:demonitor(Monitor, [flush]),
            Reply;
        {'DOWN', Monitor, process, Pid, _Reason} ->
            {error, <<"owner_unavailable">>}
    after remaining_ms(Deadline) ->
        Pid ! {self(), Ref, insert_cancel},
        erlang:demonitor(Monitor, [flush]),
        {error, <<"timeout">>}
    end.

await_insert_confirmation(Pid, Ref, Monitor) ->
    receive
        {Ref, {insert_confirmed, Reply}} ->
            erlang:demonitor(Monitor, [flush]),
            Reply;
        {Ref, Reply} ->
            erlang:demonitor(Monitor, [flush]),
            Reply;
        {'DOWN', Monitor, process, Pid, _Reason} ->
            {error, <<"owner_unavailable">>}
    end.

remaining_ms(Deadline) ->
    max(0, Deadline - erlang:monotonic_time(millisecond)).

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

%% Tables maps a table name to
%% {SessionTable, ClientCountTable, MaxEntries, MaxEntriesPerClient}.
loop(Tables) ->
    loop(Tables, #{}).

loop(Tables, Pending) ->
    receive
        {From, Ref, insert_ack} ->
            case maps:take(Ref, Pending) of
                {{From, Monitor, Deadline, Handle, Key}, Pending2} ->
                    erlang:demonitor(Monitor, [flush]),
                    case erlang:monotonic_time(millisecond) >= Deadline of
                        true ->
                            rollback_insert(Handle, Key, Tables),
                            From ! {Ref, {error, <<"timeout">>}};
                        false ->
                            From ! {Ref, {insert_confirmed, {ok, nil}}}
                    end,
                    loop(Tables, Pending2);
                _ ->
                    loop(Tables, Pending)
            end;
        {From, Ref, insert_cancel} ->
            case maps:take(Ref, Pending) of
                {{From, Monitor, _Deadline, Handle, Key}, Pending2} ->
                    erlang:demonitor(Monitor, [flush]),
                    rollback_insert(Handle, Key, Tables),
                    loop(Tables, Pending2);
                _ ->
                    loop(Tables, Pending)
            end;
        {insert_deadline, Ref} ->
            case maps:take(Ref, Pending) of
                {{From, Monitor, _Deadline, Handle, Key}, Pending2} ->
                    erlang:demonitor(Monitor, [flush]),
                    rollback_insert(Handle, Key, Tables),
                    From ! {Ref, {error, <<"timeout">>}},
                    loop(Tables, Pending2);
                error ->
                    loop(Tables, Pending)
            end;
        {'DOWN', Monitor, process, _Pid, _Reason} ->
            case take_pending_by_monitor(Monitor, maps:to_list(Pending)) of
                {ok, Ref, {_From, Monitor, _Deadline, Handle, Key}} ->
                    rollback_insert(Handle, Key, Tables),
                    loop(Tables, maps:remove(Ref, Pending));
                error ->
                    loop(Tables, Pending)
            end;
        {From, Ref, {create, Name, MaxEntries, MaxEntriesPerClient}} ->
            case maps:is_key(Name, Tables) of
                true ->
                    From ! {Ref, {error, <<"table_already_exists">>}},
                    loop(Tables, Pending);
                false ->
                    case new_table(Name, MaxEntries, MaxEntriesPerClient, Tables) of
                        {ok, Tables2} ->
                            From ! {Ref, {ok, {Name, MaxEntries,
                                               MaxEntriesPerClient}}},
                            loop(Tables2, Pending);
                        error ->
                            From ! {Ref, {error, <<"table_create_failed">>}},
                            loop(Tables, Pending)
                    end
            end;
        {From, Ref, {insert, Handle, Key, ClientKey, Value, Deadline}} ->
            {Reply, Tables2} =
                case erlang:monotonic_time(millisecond) >= Deadline of
                    true -> {{error, <<"timeout">>}, Tables};
                    false ->
                        with_table(Handle, Tables, fun(Table, Counts, MaxEntries, MaxPerClient) ->
                            insert_bounded(Table, Counts, MaxEntries, MaxPerClient,
                                           Key, ClientKey, Value)
                        end)
                end,
            case Reply of
                {ok, nil} ->
                    Monitor = erlang:monitor(process, From),
                    erlang:send_after(
                        remaining_ms(Deadline),
                        self(),
                        {insert_deadline, Ref}
                    ),
                    From ! {Ref, insert_provisional},
                    Pending2 = maps:put(
                        Ref,
                        {From, Monitor, Deadline, Handle, Key},
                        Pending
                    ),
                    loop(Tables2, Pending2);
                _ ->
                    From ! {Ref, Reply},
                    loop(Tables2, Pending)
            end;
        {From, Ref, {take, Handle, Key}} ->
            {Reply, Tables2} = with_table(Handle, Tables, fun(Table, Counts, _, _) ->
                case ets:take(Table, Key) of
                    [{Key, ClientKey, Value}] ->
                        decrement_count(Counts, ClientKey, Value),
                        {ok, Value};
                    [] -> {error, nil}
                end
            end),
            From ! {Ref, Reply},
            loop(Tables2, Pending);
        {From, Ref, {take_for_provider, Handle, Key, Provider}} ->
            {Reply, Tables2} = take_for_provider_reply(
                Handle, Key, Provider, monotonic_seconds(), Tables),
            From ! {Ref, Reply},
            loop(Tables2, Pending);
        {From, Ref, {take_for_provider, Handle, Key, Provider, Now}} ->
            {Reply, Tables2} = take_for_provider_reply(
                Handle, Key, Provider, Now, Tables),
            From ! {Ref, Reply},
            loop(Tables2, Pending);
        {From, Ref, {lookup, Handle, Key}} ->
            {Reply, Tables2} = with_table(Handle, Tables, fun(Table, _, _, _) ->
                case ets:lookup(Table, Key) of
                    [{Key, _, Value}] -> {ok, Value};
                    [] -> {error, nil}
                end
            end),
            From ! {Ref, Reply},
            loop(Tables2, Pending);
        {From, Ref, {delete_key, Handle, Key}} ->
            {Reply, Tables2} = with_table(Handle, Tables, fun(Table, Counts, _, _) ->
                case ets:take(Table, Key) of
                    [{Key, ClientKey, Value}] ->
                        decrement_count(Counts, ClientKey, Value);
                    [] -> ok
                end,
                {ok, nil}
            end),
            From ! {Ref, Reply},
            loop(Tables2, Pending);
        {From, Ref, {cleanup_expired, Handle}} ->
            {Reply, Tables2} = with_table(Handle, Tables, fun(Table, Counts, _, _) ->
                {ok, sweep_expired(Table, Counts)}
            end),
            From ! {Ref, Reply},
            loop(Tables2, Pending);
        {From, Ref, {count, Handle}} ->
            {Reply, Tables2} = with_table(Handle, Tables, fun(Table, _, _, _) ->
                {ok, ets:info(Table, size)}
            end),
            From ! {Ref, Reply},
            loop(Tables2, Pending);
        {sweep, Name} ->
            case maps:find(Name, Tables) of
                {ok, {Table, Counts, _, _}} ->
                    catch sweep_expired(Table, Counts),
                    schedule_sweep(Name);
                error ->
                    ok
            end,
            loop(Tables, Pending);
        _Unexpected ->
            loop(Tables, Pending)
    end.

take_pending_by_monitor(_Monitor, []) ->
    error;
take_pending_by_monitor(Monitor, [{Ref, {_, Monitor, _, _, _} = Value} | _]) ->
    {ok, Ref, Value};
take_pending_by_monitor(Monitor, [_ | Rest]) ->
    take_pending_by_monitor(Monitor, Rest).

rollback_insert({Name, _, _}, Key, Tables) ->
    case maps:find(Name, Tables) of
        {ok, {Table, Counts, _, _}} ->
            case ets:take(Table, Key) of
                [{Key, ClientKey, Value}] ->
                    decrement_count(Counts, ClientKey, Value);
                [] ->
                    ok
            end;
        error ->
            ok
    end;
rollback_insert(_, _, _) ->
    ok.

take_for_provider_reply(Handle, Key, Provider, Now, Tables) ->
            {Reply, Tables2} = with_table(Handle, Tables, fun(Table, Counts, _, _) ->
                case ets:lookup(Table, Key) of
                    [{Key, ClientKey,
                      {session_state, Provider, _, _, _, ExpiresAt} = Value}] ->
                        case ExpiresAt =< Now of
                            true ->
                                ets:delete(Table, Key),
                                decrement_count(Counts, ClientKey, Value),
                                {error, nil};
                            false ->
                                ets:delete(Table, Key),
                                decrement_count(Counts, ClientKey, Value),
                                {ok, Value}
                        end;
                    [{Key, _, _}] -> {error, nil};
                    [] -> {error, nil}
                end
            end),
            {Reply, Tables2}.

%% Run Fun against the table a handle names, recreating the table (empty)
%% if this owner does not know it. Returns {Reply, Tables}.
with_table({Name, MaxEntries, MaxPerClient} = _Handle, Tables, Fun) ->
    case maps:find(Name, Tables) of
        {ok, {Table, Counts, Max, PerClient}} ->
            {run(Fun, Table, Counts, Max, PerClient), Tables};
        error ->
            case new_table(Name, MaxEntries, MaxPerClient, Tables) of
                {ok, Tables2} ->
                    {ok, {Table, Counts, Max, PerClient}} = maps:find(Name, Tables2),
                    {run(Fun, Table, Counts, Max, PerClient), Tables2};
                error ->
                    {{error, <<"table_create_failed">>}, Tables}
            end
    end;
with_table(_Handle, Tables, _Fun) ->
    {{error, <<"table_not_found">>}, Tables}.

run(Fun, Table, Counts, MaxEntries, MaxPerClient) ->
    try Fun(Table, Counts, MaxEntries, MaxPerClient)
    catch _:_ -> {error, <<"ets_operation_failed">>}
    end.

new_table(Name, MaxEntries, MaxPerClient, Tables) ->
    try
        Table = ets:new(vestibule_state_store, [set, protected]),
        Counts = ets:new(vestibule_state_store_counts, [set, protected]),
        schedule_sweep(Name),
        {ok, maps:put(Name, {Table, Counts, MaxEntries, MaxPerClient}, Tables)}
    catch
        _:_ -> error
    end.

%% Insert unless the table is at capacity. At capacity, expired entries are
%% reclaimed first; only if the table is still full is the insert refused.
%% This keeps the request phase O(1) in the common case while bounding the
%% memory an unauthenticated client can pin by starting flows in a loop.
insert_bounded(Table, Counts, MaxEntries, MaxPerClient, Key, ClientKey, Value) ->
    sweep_if_full(Table, Counts, MaxEntries),
    case ClientKey of
        <<>> ->
            insert_globally_bounded(Table, Counts, MaxEntries,
                                    Key, ClientKey, Value);
        _ ->
            ClientCount = client_count(Counts, ClientKey),
            case ClientCount >= MaxPerClient
                 andalso client_has_expired(Counts, ClientKey) of
                true -> sweep_expired(Table, Counts);
                false -> ok
            end,
            CurrentClientCount = client_count(Counts, ClientKey),
            case CurrentClientCount >= MaxPerClient of
                true ->
                    {error, <<"client_limit_reached">>};
                false ->
                    insert_globally_bounded(Table, Counts, MaxEntries,
                                            Key, ClientKey, Value)
            end
    end.

client_count(Counts, ClientKey) ->
    case ets:lookup(Counts, ClientKey) of
        [{ClientKey, Expirations}] -> length(Expirations);
        [] -> 0
    end.

client_has_expired(Counts, ClientKey) ->
    Now = monotonic_seconds(),
    case ets:lookup(Counts, ClientKey) of
        [{ClientKey, Expirations}] ->
            lists:any(fun(Expiry) -> Expiry =< Now end, Expirations);
        [] -> false
    end.

sweep_if_full(Table, Counts, MaxEntries) ->
    case ets:info(Table, size) >= MaxEntries of
        true -> sweep_expired(Table, Counts);
        false -> ok
    end.

insert_globally_bounded(Table, Counts, MaxEntries, Key, ClientKey, Value) ->
    case ets:info(Table, size) >= MaxEntries of
        true -> {error, <<"store_full">>};
        false ->
            ets:insert(Table, {Key, ClientKey, Value}),
            increment_count(Counts, ClientKey, Value),
            {ok, nil}
    end.

increment_count(Counts, ClientKey, Value) ->
    Expiry = value_expiry(Value),
    case ets:lookup(Counts, ClientKey) of
        [{ClientKey, Expirations}] ->
            ets:insert(Counts, {ClientKey, [Expiry | Expirations]});
        [] ->
            ets:insert(Counts, {ClientKey, [Expiry]})
    end.

decrement_count(Counts, ClientKey, Value) ->
    decrement_expiry(Counts, ClientKey, value_expiry(Value)).

decrement_expiry(Counts, ClientKey, Expiry) ->
    case ets:lookup(Counts, ClientKey) of
        [{ClientKey, Expirations}] ->
            case lists:delete(Expiry, Expirations) of
                [] -> ets:delete(Counts, ClientKey);
                Remaining -> ets:insert(Counts, {ClientKey, Remaining})
            end;
        [] -> ok
    end.

value_expiry({session_state, _, _, _, _, ExpiresAt}) -> ExpiresAt;
value_expiry(_) -> infinity.

schedule_sweep(Name) ->
    erlang:send_after(?SWEEP_INTERVAL_MS, self(), {sweep, Name}).

%% Delete every session whose expires_at is at or before now. Runs as a
%% single select followed by count maintenance. The expiry is a BEAM monotonic
%% second, so wall-clock changes do not affect session lifetime.
sweep_expired(Table, Counts) ->
    Now = monotonic_seconds(),
    Expired = ets:select(Table, [{
        {'$1', '$2', {session_state, '_', '_', '_', '_', '$3'}},
        [{'=<', '$3', {const, Now}}],
        [{{'$1', '$2', '$3'}}]
    }]),
    lists:foreach(fun({Key, ClientKey, ExpiresAt}) ->
        ets:delete(Table, Key),
        decrement_expiry(Counts, ClientKey, ExpiresAt)
    end, Expired),
    length(Expired).

monotonic_seconds() ->
    erlang:monotonic_time(second).
