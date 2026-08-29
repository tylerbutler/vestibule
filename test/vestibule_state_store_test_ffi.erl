-module(vestibule_state_store_test_ffi).

-export([state_store_survives_creator_process_exit/0, count_store_entries/1,
         trigger_owner_sweep/1, kill_owner/0]).

state_store_survives_creator_process_exit() ->
    Name = <<"vestibule_owner_lifetime_test">>,
    Key = <<"session">>,
    Value = <<"stored">>,
    Parent = self(),
    Pid = spawn(fun() ->
        Result =
            case vestibule_state_store_ffi:create_table(Name, 100000) of
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
    case vestibule_state_store_ffi:lookup({Name, 100000}, Key) of
        {ok, Value} -> true;
        _ -> false
    end.

count_store_entries(Name) ->
    case vestibule_state_store_ffi:count({Name, 100000}) of
        {ok, Count} -> Count;
        {error, _} -> -1
    end.

%% Deliver the owner's periodic sweep tick immediately. The owner processes
%% its mailbox in order, so a subsequent synchronous call (e.g. count/1)
%% observes the sweep's effect.
trigger_owner_sweep(Name) ->
    vestibule_state_store_owner ! {sweep, Name},
    nil.

%% Kill the owner process and wait until its registered name is gone, so the
%% next store call observes a dead owner rather than racing the exit.
kill_owner() ->
    case whereis(vestibule_state_store_owner) of
        undefined -> nil;
        Pid ->
            Monitor = erlang:monitor(process, Pid),
            exit(Pid, kill),
            receive {'DOWN', Monitor, process, Pid, _} -> ok after 5000 -> ok end,
            nil
    end.
