-module(vestibule_state_store_test_ffi).

-export([state_store_survives_creator_process_exit/0, count_store_entries/1,
         trigger_owner_sweep/1, kill_owner/0, concurrent_take_winner_count/0,
         owner_death_during_call_is_controlled/0, consume_after_expiry/3,
         format_store_entry/2, delayed_consume_rejects_expired/0,
         timed_out_insert_does_not_commit/0,
         post_check_timeout_rolls_back_insert/0]).

state_store_survives_creator_process_exit() ->
    Name = <<"vestibule_owner_lifetime_test">>,
    Key = <<"session">>,
    Value = <<"stored">>,
    Parent = self(),
    Pid = spawn(fun() ->
        Result =
            case vestibule_state_store_ffi:create_table(Name, 4096, 8) of
                {ok, Store} ->
                    vestibule_state_store_ffi:insert(Store, Key, <<>>, Value);
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
    case vestibule_state_store_ffi:lookup({Name, 4096, 8}, Key) of
        {ok, Value} -> true;
        _ -> false
    end.

count_store_entries(Name) ->
    case vestibule_state_store_ffi:count({Name, 4096, 8}) of
        {ok, Count} -> Count;
        {error, _} -> -1
    end.

format_store_entry({state_store, Store}, SessionId) ->
    case vestibule_state_store_ffi:lookup(Store, SessionId) of
        {ok, Value} -> unicode:characters_to_binary(io_lib:format("~p", [Value]));
        {error, _} -> <<>>
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

concurrent_take_winner_count() ->
    Name = <<"vestibule_concurrent_take_test">>,
    Key = <<"session">>,
    {ok, Store} = vestibule_state_store_ffi:create_table(Name, 8, 2),
    Value =
        {session_state, <<"test">>, <<"state">>, <<"verifier">>, none,
         erlang:monotonic_time(second) + 600},
    {ok, nil} =
        vestibule_state_store_ffi:insert(Store, Key, <<"client">>, Value),
    Parent = self(),
    Ready = make_ref(),
    Go = make_ref(),
    Worker = fun() ->
        Parent ! {Ready, self()},
        receive Go -> ok end,
        Parent ! {result,
                  vestibule_state_store_ffi:take_for_provider(
                    Store, Key, <<"test">>)}
    end,
    Pid1 = spawn(Worker),
    Pid2 = spawn(Worker),
    receive {Ready, Pid1} -> ok end,
    receive {Ready, Pid2} -> ok end,
    Pid1 ! Go,
    Pid2 ! Go,
    Results = [receive {result, Result1} -> Result1 end,
               receive {result, Result2} -> Result2 end],
    length([ok || {ok, _} <- Results]).

delayed_consume_rejects_expired() ->
    Name = <<"vestibule_delayed_consume_expiry_test">>,
    Key = <<"session">>,
    {ok, Store} = vestibule_state_store_ffi:create_table(Name, 8, 2),
    ExpiresAt = erlang:monotonic_time(second) + 1,
    Value = {session_state, <<"test">>, <<"state">>, <<"verifier">>, none,
             ExpiresAt},
    {ok, nil} =
        vestibule_state_store_ffi:insert(Store, Key, <<"client">>, Value),
    Owner = whereis(vestibule_state_store_owner),
    true = erlang:suspend_process(Owner),
    Parent = self(),
    Caller = spawn(fun() ->
        Parent ! {consume_started, self()},
        Parent ! {consume_finished,
                  vestibule_state_store_ffi:take_for_provider(
                    Store, Key, <<"test">>)}
    end),
    receive {consume_started, Caller} -> ok end,
    wait_until_after(ExpiresAt),
    true = erlang:resume_process(Owner),
    receive
        {consume_finished, {error, nil}} -> true;
        {consume_finished, _} -> false
    after 5000 ->
        false
    end.

wait_until_after(ExpiresAt) ->
    case erlang:monotonic_time(second) > ExpiresAt of
        true -> ok;
        false ->
            erlang:yield(),
            wait_until_after(ExpiresAt)
    end.

timed_out_insert_does_not_commit() ->
    Name = <<"vestibule_timed_out_insert_test">>,
    Key = <<"session">>,
    {ok, Store} = vestibule_state_store_ffi:create_table(Name, 8, 2),
    Owner = whereis(vestibule_state_store_owner),
    true = erlang:suspend_process(Owner),
    Parent = self(),
    Value = {session_state, <<"test">>, <<"state">>, <<"verifier">>, none,
             erlang:monotonic_time(second) + 600},
    Caller = spawn(fun() ->
        Parent ! {insert_started, self()},
        Parent ! {insert_finished,
                  vestibule_state_store_ffi:insert(
                    Store, Key, <<"client">>, Value)}
    end),
    receive {insert_started, Caller} -> ok end,
    TimedOut = receive
        {insert_finished, {error, <<"timeout">>}} -> true;
        {insert_finished, _} -> false
    after 6000 ->
        false
    end,
    true = erlang:resume_process(Owner),
    Missing = case vestibule_state_store_ffi:lookup(Store, Key) of
        {error, nil} -> true;
        _ -> false
    end,
    TimedOut andalso Missing.

post_check_timeout_rolls_back_insert() ->
    Name = <<"vestibule_post_check_insert_timeout_test">>,
    Key = <<"abandoned">>,
    {ok, Store} = vestibule_state_store_ffi:create_table(Name, 8, 1),
    Owner = whereis(vestibule_state_store_owner),
    Deadline = erlang:monotonic_time(millisecond) + 100,
    Value = {session_state, <<"test">>, <<"state">>, <<"verifier">>, none,
             erlang:monotonic_time(second) + 600},
    Ref = make_ref(),
    Owner ! {self(), Ref,
             {insert, Store, Key, <<"client">>, Value, Deadline}},
    receive {Ref, insert_provisional} -> ok after 1000 -> error(no_provisional) end,
    true = erlang:suspend_process(Owner),
    wait_until_ms_after(Deadline),
    true = erlang:resume_process(Owner),
    Missing = case vestibule_state_store_ffi:lookup(Store, Key) of
        {error, nil} -> true;
        _ -> false
    end,
    CountReconciled = case vestibule_state_store_ffi:count(Store) of
        {ok, 0} -> true;
        _ -> false
    end,
    Replacement = vestibule_state_store_ffi:insert(
        Store, <<"replacement">>, <<"client">>, Value),
    Missing andalso CountReconciled andalso Replacement =:= {ok, nil}.

wait_until_ms_after(Deadline) ->
    case erlang:monotonic_time(millisecond) > Deadline of
        true -> ok;
        false ->
            erlang:yield(),
            wait_until_ms_after(Deadline)
    end.

owner_death_during_call_is_controlled() ->
    Name = <<"vestibule_owner_mid_call_test">>,
    {ok, Store} = vestibule_state_store_ffi:create_table(Name, 8, 2),
    Owner = whereis(vestibule_state_store_owner),
    true = erlang:suspend_process(Owner),
    Parent = self(),
    Caller = spawn(fun() ->
        Parent ! {started, self()},
        Result = vestibule_state_store_ffi:lookup(Store, <<"missing">>),
        Parent ! {finished, Result}
    end),
    receive {started, Caller} -> ok end,
    Monitor = erlang:monitor(process, Owner),
    exit(Owner, kill),
    receive {'DOWN', Monitor, process, Owner, _} -> ok end,
    receive
        {finished, {error, <<"owner_unavailable">>}} -> true;
        {finished, _} -> false
    after 5000 ->
        false
    end.

consume_after_expiry({state_store, Store}, SessionId, Provider) ->
    vestibule_state_store_ffi:take_for_provider_at(
      Store, SessionId, Provider, erlang:monotonic_time(second) + 3600).
