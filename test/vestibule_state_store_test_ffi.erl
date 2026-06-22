-module(vestibule_state_store_test_ffi).

-export([state_store_survives_creator_process_exit/0, count_store_entries/1]).

state_store_survives_creator_process_exit() ->
    Name = <<"vestibule_owner_lifetime_test">>,
    Key = <<"session">>,
    Value = <<"stored">>,
    Parent = self(),
    Pid = spawn(fun() ->
        Result =
            case vestibule_state_store_ffi:create_table(Name) of
                {ok, Store} ->
                    vestibule_state_store_ffi:insert(Store, Key, Value);
                Error ->
                    Error
            end,
        Parent ! {created, Result}
    end),
    Monitor = erlang:monitor(process, Pid),
    receive
        {created, {ok, nil}} -> ok;
        {created, _} -> false
    after 5000 ->
        false
    end,
    receive
        {'DOWN', Monitor, process, Pid, _Reason} -> ok
    after 5000 ->
        false
    end,
    case vestibule_state_store_ffi:lookup(Name, Key) of
        {ok, Value} -> true;
        _ -> false
    end.

count_store_entries(Name) ->
    case vestibule_state_store_ffi:count(Name) of
        {ok, Count} -> Count;
        {error, _} -> -1
    end.
