-module(vestibule_wisp_state_store_ffi).

-export([create_table/1, insert/3, take/2, lookup/2, delete_key/2]).

-define(SERVER, vestibule_wisp_state_store_owner).

create_table(Name) ->
    call({create, Name}).

insert(Table, Key, Value) ->
    call({insert, Table, Key, Value}).

take(Table, Key) ->
    call({take, Table, Key}).

lookup(Table, Key) ->
    call({lookup, Table, Key}).

delete_key(Table, Key) ->
    call({delete_key, Table, Key}).

call(Request) ->
    case ensure_owner() of
        ok ->
            Ref = make_ref(),
            ?SERVER ! {self(), Ref, Request},
            receive
                {Ref, Reply} -> Reply
            after 5000 ->
                {error, nil}
            end;
        error ->
            {error, nil}
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
                    error
            end;
        _ ->
            ok
    end.

loop(Tables) ->
    receive
        {From, Ref, {create, Name}} ->
            case maps:is_key(Name, Tables) of
                true ->
                    From ! {Ref, {error, nil}},
                    loop(Tables);
                false ->
                    try
                        Table = ets:new(vestibule_wisp_state_store,
                                        [set, protected]),
                        From ! {Ref, {ok, Name}},
                        loop(maps:put(Name, Table, Tables))
                    catch
                        _:_ ->
                            From ! {Ref, {error, nil}},
                            loop(Tables)
                    end
            end;
        {From, Ref, {insert, Name, Key, Value}} ->
            From ! {Ref, with_table(Name, Tables, fun(Table) ->
                ets:insert(Table, {Key, Value}),
                {ok, nil}
            end)},
            loop(Tables);
        {From, Ref, {take, Name, Key}} ->
            From ! {Ref, with_table(Name, Tables, fun(Table) ->
                case ets:take(Table, Key) of
                    [{Key, Value}] -> {ok, Value};
                    [] -> {error, nil}
                end
            end)},
            loop(Tables);
        {From, Ref, {lookup, Name, Key}} ->
            From ! {Ref, with_table(Name, Tables, fun(Table) ->
                case ets:lookup(Table, Key) of
                    [{Key, Value}] -> {ok, Value};
                    [] -> {error, nil}
                end
            end)},
            loop(Tables);
        {From, Ref, {delete_key, Name, Key}} ->
            From ! {Ref, with_table(Name, Tables, fun(Table) ->
                ets:delete(Table, Key),
                {ok, nil}
            end)},
            loop(Tables)
    end.

with_table(Name, Tables, Fun) ->
    case maps:find(Name, Tables) of
        {ok, Table} ->
            try Fun(Table)
            catch _:_ -> {error, nil}
            end;
        error ->
            {error, nil}
    end.
