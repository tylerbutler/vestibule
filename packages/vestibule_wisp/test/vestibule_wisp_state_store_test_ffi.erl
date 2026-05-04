-module(vestibule_wisp_state_store_test_ffi).

-export([state_store_survives_creator_process_exit/0]).

state_store_survives_creator_process_exit() ->
    Name = <<"vestibule_wisp_owner_lifetime_test">>,
    Key = <<"session">>,
    Value = <<"stored">>,
    Parent = self(),
    Pid = spawn(fun() ->
        Result =
            case vestibule_wisp_state_store_ffi:create_table(Name) of
                {ok, Store} ->
                    vestibule_wisp_state_store_ffi:insert(Store, Key, Value);
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
    case vestibule_wisp_state_store_ffi:lookup(Name, Key) of
        {ok, Value} -> true;
        _ -> false
    end.
