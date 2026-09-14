-module(vestibule_public_http_test_ffi).
-export([
    oversized_content_length/0,
    chunked_overflow/0,
    close_delimited_overflow/0,
    just_under_limit/0,
    close_delimited_success/0,
    invalid_utf8_header/0,
    concurrent_cleanup/0,
    response_timeout/0,
    unsupported_transfer_coding/0,
    unsupported_content_coding/0,
    ambiguous_framing/0,
    proxy_is_ignored/0,
    request_budgets_precede_dns/0,
    resolver_result_is_pinned/0,
    mixed_dns_answer_is_rejected/0,
    tls_uses_original_host_and_system_ca/0,
    tls_handshake_matrix/0,
    admission_is_bounded_and_reusable/0,
    admission_timeout_is_cancelled/0,
    late_release_is_reclaimed/0,
    caller_death_cleans_up/0,
    deadline_releases_admission/0
]).

oversized_content_length() ->
    {Result, Closed} = exchange(
        fun(Socket) ->
            ok = gen_tcp:send(
                Socket,
                <<"HTTP/1.1 500 Error\r\nContent-Length: 17\r\n\r\n">>
            ),
            peer_closed(Socket)
        end,
        16,
        1000
    ),
    Closed andalso oversized_error(Result, <<"Content-Length: 17">>).

chunked_overflow() ->
    {Result, Closed} = exchange(
        fun(Socket) ->
            ok = gen_tcp:send(
                Socket,
                <<"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
                    "a\r\n0123456789\r\n7\r\n">>
            ),
            peer_closed(Socket)
        end,
        16,
        1000
    ),
    Closed andalso oversized_error(Result, <<"streaming chunked">>).

close_delimited_overflow() ->
    {Result, Closed} = exchange(
        fun(Socket) ->
            ok = gen_tcp:send(
                Socket,
                <<"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n",
                    "12345678901234567">>
            ),
            peer_closed(Socket)
        end,
        16,
        1000
    ),
    Closed andalso oversized_error(Result, <<"streaming close-delimited">>).

just_under_limit() ->
    Body = <<"123456789012345">>,
    {Result, Closed} = exchange(
        fun(Socket) ->
            ok = gen_tcp:send(
                Socket,
                [
                    <<"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n",
                        "Content-Type: application/json\r\n\r\n">>,
                    Body
                ]
            ),
            peer_closed(Socket)
        end,
        16,
        1000
    ),
    Closed andalso
        Result =:= {
            ok,
            {200,
                [
                    {<<"Content-Length">>, <<"15">>},
                    {<<"Content-Type">>, <<"application/json">>}
                ],
                Body}
        }.

close_delimited_success() ->
    Body = <<"normal provider response">>,
    {Result, _Closed} = exchange(
        fun(Socket) ->
            ok = gen_tcp:send(
                Socket,
                [<<"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n">>, Body]
            ),
            ok
        end,
        64,
        1000
    ),
    Result =:= {
        ok,
        {200, [{<<"Connection">>, <<"close">>}], Body}
    }.

invalid_utf8_header() ->
    {Result, Closed} = exchange(
        fun(Socket) ->
            ok = gen_tcp:send(
                Socket,
                <<"HTTP/1.1 200 OK\r\nLink: \xff\r\nContent-Length: 0\r\n\r\n">>
            ),
            peer_closed(Socket)
        end,
        16,
        1000
    ),
    Closed andalso
        case Result of
            {error, {response_error, Reason}} ->
                binary:match(Reason, <<"invalid header">>) =/= nomatch;
            _ ->
                false
        end.

response_timeout() ->
    {Result, Closed} = exchange(
        fun(Socket) ->
            timer:sleep(200),
            peer_closed(Socket)
        end,
        16,
        75
    ),
    Closed andalso
        case Result of
            {error, {transport, Reason}} ->
                binary:match(Reason, <<"timed out">>) =/= nomatch;
            _ ->
                false
        end.

unsupported_transfer_coding() ->
    {Result, Closed} = exchange(
        fun(Socket) ->
            ok = gen_tcp:send(
                Socket,
                <<"HTTP/1.1 200 OK\r\n",
                    "Transfer-Encoding: gzip, chunked\r\n\r\n",
                    "0\r\n\r\n">>
            ),
            peer_closed(Socket)
        end,
        16,
        1000
    ),
    Closed andalso response_error(Result, <<"transfer-encoding">>).

unsupported_content_coding() ->
    {Result, Closed} = exchange(
        fun(Socket) ->
            ok = gen_tcp:send(
                Socket,
                <<"HTTP/1.1 200 OK\r\n",
                    "Content-Encoding: gzip\r\n",
                    "Content-Length: 0\r\n\r\n">>
            ),
            peer_closed(Socket)
        end,
        16,
        1000
    ),
    Closed andalso response_error(Result, <<"content-encoding">>).

ambiguous_framing() ->
    {Result, Closed} = exchange(
        fun(Socket) ->
            ok = gen_tcp:send(
                Socket,
                <<"HTTP/1.1 200 OK\r\n",
                    "Transfer-Encoding: chunked\r\n",
                    "Content-Length: 0\r\n\r\n",
                    "0\r\n\r\n">>
            ),
            peer_closed(Socket)
        end,
        16,
        1000
    ),
    Closed andalso response_error(Result, <<"both Transfer-Encoding">>).

proxy_is_ignored() ->
    Previous = os:getenv("HTTP_PROXY"),
    true = os:putenv("HTTP_PROXY", "http://127.0.0.1:1"),
    try
        close_delimited_success()
    after
        restore_env("HTTP_PROXY", Previous)
    end.

request_budgets_precede_dns() ->
    OversizedUrl = request(<<"/", (binary:copy(<<"x">>, 8192))/binary>>),
    OversizedHeaders =
        setelement(
            3,
            request(<<"/">>),
            [{<<"x">>, binary:copy(<<"x">>, 65536)}]
        ),
    OversizedBody =
        setelement(4, request(<<"/">>), binary:copy(<<"x">>, 1048577)),
    request_budget_error(
        vestibule_public_http_ffi:send(OversizedUrl, 16),
        <<"URL exceeds">>
    )
        andalso request_budget_error(
            vestibule_public_http_ffi:send(OversizedHeaders, 16),
            <<"headers exceed">>
        )
        andalso request_budget_error(
            vestibule_public_http_ffi:send(OversizedBody, 16),
            <<"body exceeds">>
        ).

resolver_result_is_pinned() ->
    Parent = self(),
    Resolver = fun(<<"provider.example">>) -> {ok, [{8, 8, 8, 8}]} end,
    Transport = fun(
        _Method,
        _Headers,
        _Body,
        _Scheme,
        Host,
        _Port,
        _Path,
        _Query,
        Address,
        _Limit,
        _Timeout
    ) ->
        Parent ! {pinned, Host, Address},
        {ok, {200, [], <<>>}}
    end,
    Result = vestibule_public_http_ffi:send_with(
        request(<<"/jwks">>), 16, Resolver, Transport, 1000
    ),
    Result =:= {ok, {response, 200, [], <<>>}}
        andalso
            receive
                {pinned, <<"provider.example">>, {8, 8, 8, 8}} -> true
            after 0 ->
                false
            end.

mixed_dns_answer_is_rejected() ->
    Parent = self(),
    Resolver = fun(<<"provider.example">>) ->
        {ok, [{8, 8, 8, 8}, {127, 0, 0, 1}]}
    end,
    Transport = fun(_, _, _, _, _, _, _, _, _, _, _) ->
        Parent ! transport_called,
        {ok, {200, [], <<>>}}
    end,
    Result = vestibule_public_http_ffi:send_with(
        request(<<"/discovery">>), 16, Resolver, Transport, 1000
    ),
    unsafe_target(Result)
        andalso
            receive
                transport_called -> false
            after 0 ->
                true
            end.

tls_uses_original_host_and_system_ca() ->
    HostOptions =
        vestibule_public_http_transport:tls_options(
            <<"Login.Provider.Example.">>
        ),
    IpOptions =
        vestibule_public_http_transport:tls_options(<<"8.8.8.8">>),
    {customize_hostname_check, HostnameChecks} =
        lists:keyfind(customize_hostname_check, 1, HostOptions),
    {match_fun, MatchHostname} = lists:keyfind(
        match_fun, 1, HostnameChecks
    ),
    lists:keyfind(verify, 1, HostOptions) =:= {verify, verify_peer}
        andalso lists:keymember(cacerts, 1, HostOptions)
        andalso lists:keyfind(server_name_indication, 1, HostOptions) =:=
            {server_name_indication, "Login.Provider.Example"}
        andalso MatchHostname(
            {dns_id, "Login.Provider.Example"},
            {dNSName, "login.provider.example"}
        )
        andalso
            not MatchHostname(
                {dns_id, "Login.Provider.Example"},
                {dNSName, "wrong.example"}
            )
        andalso (
            MatchHostname(
                {ip, {8, 8, 8, 8}},
                {dNSName, "8.8.8.8"}
            ) =:= default
        )
        andalso
            not lists:keymember(server_name_indication, 1, IpOptions).

tls_handshake_matrix() ->
    {ok, _} = application:ensure_all_started(ssl),
    Host = unicode:characters_to_binary(net_adm:localhost()),
    Root = public_key:pkix_test_root_cert(
        "Vestibule HTTP Test Root",
        [{key, {rsa, 2048, 65537}}]
    ),
    Valid = tls_test_config(Root, []),
    OtherRoot = public_key:pkix_test_root_cert(
        "Vestibule Untrusted Test Root",
        [{key, {rsa, 2048, 65537}}]
    ),
    Expired = tls_test_config(Root, [
        {validity, expired_validity()}
    ]),
    tls_success_with_original_sni(Host, Valid)
        andalso tls_rejected(
            Host,
            Valid,
            [maps:get(cert, OtherRoot)],
            <<"unknown_ca">>
        )
        andalso tls_rejected(
            Host,
            Expired,
            maps:get(cacerts, Valid),
            <<"certificate_expired">>
        )
        andalso tls_rejected(
            <<"wrong.example">>,
            Valid,
            maps:get(cacerts, Valid),
            <<"hostname_check_failed">>
        )
        andalso tls_rejected(
            <<"127.0.0.1">>,
            Valid,
            maps:get(cacerts, Valid),
            <<"hostname_check_failed">>
        ).

tls_test_config(Root, PeerOptions) ->
    maps:from_list(
        public_key:pkix_test_data(#{
            root => Root,
            peer => [{key, {rsa, 2048, 65537}} | PeerOptions]
        })
    ).

expired_validity() ->
    Today = calendar:date_to_gregorian_days(date()),
    {
        calendar:gregorian_days_to_date(Today - 2),
        calendar:gregorian_days_to_date(Today - 1)
    }.

tls_success_with_original_sni(Host, Config) ->
    {Result, ServerResult} = tls_exchange(Host, Config, maps:get(cacerts, Config)),
    Result =:= {ok, {200, [{<<"Content-Length">>, <<"0">>}], <<>>}}
        andalso ServerResult =:= {ok, binary_to_list(Host)}.

tls_rejected(Host, Config, TrustedCacerts, ExpectedReason) ->
    {Result, _ServerResult} = tls_exchange(Host, Config, TrustedCacerts),
    case Result of
        {error, {transport, Reason}} ->
            binary:match(Reason, <<"tls_connect">>) =/= nomatch
                andalso binary:match(Reason, ExpectedReason) =/= nomatch;
        _ ->
            false
    end.

tls_exchange(Host, Config, TrustedCacerts) ->
    {ok, Listener} = ssl:listen(
        0,
        [
            binary,
            {active, false},
            {reuseaddr, true},
            {cert, maps:get(cert, Config)},
            {key, maps:get(key, Config)}
        ]
    ),
    {ok, {_Address, Port}} = ssl:sockname(Listener),
    Parent = self(),
    Server = spawn(fun() -> tls_server(Parent, Listener) end),
    Result = vestibule_public_http_transport:request_with_cacerts(
        get,
        [{"host", binary_to_list(Host)}, {"connection", "close"}],
        <<>>,
        https,
        Host,
        {some, Port},
        <<"/resource">>,
        none,
        {127, 0, 0, 1},
        16,
        2000,
        TrustedCacerts
    ),
    catch ssl:close(Listener),
    ServerResult =
        receive
            {tls_server_done, Server, Value} -> Value
        after 3000 ->
            timeout
        end,
    {Result, ServerResult}.

tls_server(Parent, Listener) ->
    Result =
        case ssl:transport_accept(Listener, 2000) of
            {ok, TransportSocket} ->
                case ssl:handshake(TransportSocket, 2000) of
                    {ok, Socket} ->
                        {ok, ConnectionInfo} =
                            ssl:connection_information(
                                Socket, [sni_hostname]
                            ),
                        Sni = proplists:get_value(
                            sni_hostname, ConnectionInfo
                        ),
                        ok = receive_tls_request_headers(Socket, <<>>),
                        ok = ssl:send(
                            Socket,
                            <<"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n">>
                        ),
                        ssl:close(Socket),
                        {ok, Sni};
                    {error, Reason} ->
                        {handshake_error, Reason}
                end;
            {error, Reason} ->
                {accept_error, Reason}
        end,
    Parent ! {tls_server_done, self(), Result}.

receive_tls_request_headers(Socket, Buffer) ->
    case binary:match(Buffer, <<"\r\n\r\n">>) of
        nomatch ->
            case ssl:recv(Socket, 0, 2000) of
                {ok, Data} ->
                    receive_tls_request_headers(
                        Socket, <<Buffer/binary, Data/binary>>
                    );
                {error, Reason} ->
                    {error, Reason}
            end;
        _ ->
            ok
    end.

admission_is_bounded_and_reusable() ->
    Parent = self(),
    Limit = vestibule_public_http_ffi:admission_limit(),
    Resolver = fun(_) -> {ok, [{8, 8, 8, 8}]} end,
    BlockingTransport = fun(_, _, _, _, _, _, _, _, _, _, _) ->
        Parent ! {transport_started, self()},
        receive
            continue -> {ok, {200, [], <<>>}}
        end
    end,
    Callers = [
        spawn(fun() ->
            Result = vestibule_public_http_ffi:send_with(
                request(<<"/slow">>),
                16,
                Resolver,
                BlockingTransport,
                5000
            ),
            Parent ! {request_done, self(), Result}
        end)
     || _ <- lists:seq(1, Limit)
    ],
    Workers = collect_started(Limit, []),
    Rejected = admission_full(
        vestibule_public_http_ffi:send_with(
            request(<<"/rejected">>),
            16,
            Resolver,
            success_transport(),
            1000
        )
    ),
    [Worker ! continue || Worker <- Workers],
    Completed = collect_done(Callers),
    Reused =
        vestibule_public_http_ffi:send_with(
            request(<<"/reused">>),
            16,
            Resolver,
            success_transport(),
            1000
        ) =:= {ok, {response, 200, [], <<>>}},
    length(Workers) =:= Limit andalso Rejected andalso Completed andalso Reused.

admission_timeout_is_cancelled() ->
    ensure_admission_server(),
    Server = whereis(vestibule_public_http_admission),
    true = erlang:suspend_process(Server),
    {TimedOut, Queued, Caller} =
        try
            admission_timeout_while_suspended(Server)
        after
            true = erlang:resume_process(Server)
        end,
    barrier(Server),
    Reusable = admission_is_bounded_and_reusable(),
    Caller ! finish,
    TimedOut andalso Queued andalso Reusable.

late_release_is_reclaimed() ->
    ensure_admission_server(),
    Server = whereis(vestibule_public_http_admission),
    Parent = self(),
    Resolver = fun(_) -> {ok, [{8, 8, 8, 8}]} end,
    BlockingTransport = fun(_, _, _, _, _, _, _, _, _, _, _) ->
        Parent ! {release_worker, self()},
        receive
            continue -> {ok, {200, [], <<>>}}
        end
    end,
    Caller = spawn(fun() ->
        Result = vestibule_public_http_ffi:send_with(
            request(<<"/late-release">>),
            16,
            Resolver,
            BlockingTransport,
            5000
        ),
        Parent ! {late_release_result, self(), Result}
    end),
    Worker =
        receive
            {release_worker, Pid} -> Pid
        after 1000 ->
            timeout
        end,
    case Worker of
        timeout ->
            false;
        _ ->
            true = erlang:suspend_process(Server),
            Result =
                try
                    Worker ! continue,
                    receive
                        {late_release_result, Caller, Value} -> Value
                    after 2000 ->
                        timeout
                    end
                after
                    true = erlang:resume_process(Server)
                end,
            barrier(Server),
            Result =:= {ok, {response, 200, [], <<>>}}
                andalso admission_is_bounded_and_reusable()
    end.

caller_death_cleans_up() ->
    Parent = self(),
    Resolver = fun(_) -> {ok, [{8, 8, 8, 8}]} end,
    BlockingTransport = fun(_, _, _, _, _, _, _, _, _, _, _) ->
        Parent ! {cancel_worker, self()},
        receive
            continue -> {ok, {200, [], <<>>}}
        end
    end,
    Caller = spawn(fun() ->
        vestibule_public_http_ffi:send_with(
            request(<<"/cancel">>),
            16,
            Resolver,
            BlockingTransport,
            5000
        )
    end),
    Worker =
        receive
            {cancel_worker, Pid} -> Pid
        after 1000 ->
            timeout
        end,
    case Worker of
        timeout ->
            false;
        _ ->
            WorkerMonitor = erlang:monitor(process, Worker),
            Server = whereis(vestibule_public_http_admission),
            {monitored_by, CallerObservers} =
                process_info(Caller, monitored_by),
            Coordinator = find_coordinator(CallerObservers, Server),
            {monitored_by, CoordinatorObservers} =
                process_info(Coordinator, monitored_by),
            CoordinatorMonitor = erlang:monitor(process, Coordinator),
            OwnershipTransferred =
                not lists:member(Server, CallerObservers)
                    andalso lists:member(Server, CoordinatorObservers),
            exit(Caller, kill),
            WorkerStopped =
                receive
                    {'DOWN', WorkerMonitor, process, Worker, _} -> true
                after 1000 ->
                    false
                end,
            CoordinatorStopped =
                receive
                    {'DOWN', CoordinatorMonitor, process, Coordinator, _} -> true
                after 1000 ->
                    false
                end,
            barrier(Server),
            OwnershipTransferred
                andalso WorkerStopped
                andalso CoordinatorStopped
                andalso admission_is_bounded_and_reusable()
    end.

deadline_releases_admission() ->
    Resolver = fun(_) -> {ok, [{8, 8, 8, 8}]} end,
    BlockingTransport = fun(_, _, _, _, _, _, _, _, _, _, _) ->
        receive
            continue -> {ok, {200, [], <<>>}}
        end
    end,
    TimedOut = request_timeout(
        vestibule_public_http_ffi:send_with(
            request(<<"/timeout">>),
            16,
            Resolver,
            BlockingTransport,
            50
        )
    ),
    Reused =
        vestibule_public_http_ffi:send_with(
            request(<<"/after-timeout">>),
            16,
            Resolver,
            success_transport(),
            1000
        ) =:= {ok, {response, 200, [], <<>>}},
    TimedOut andalso Reused.

concurrent_cleanup() ->
    Parent = self(),
    Count = 24,
    [
        spawn(fun() ->
            Result = oversized_content_length(),
            MailboxClean =
                receive
                    {http, _} -> false
                after 0 ->
                    true
                end,
            Parent ! {concurrent_result, self(), Result andalso MailboxClean}
        end)
     || _ <- lists:seq(1, Count)
    ],
    collect_concurrent(Count, true).

collect_concurrent(0, Result) ->
    Result;
collect_concurrent(Remaining, Result) ->
    receive
        {concurrent_result, _Pid, Value} ->
            collect_concurrent(Remaining - 1, Result andalso Value)
    after 5000 ->
        false
    end.

exchange(ServerAction, Limit, Timeout) ->
    {ok, Listener} = gen_tcp:listen(
        0,
        [
            binary,
            {active, false},
            {packet, raw},
            {reuseaddr, true},
            {ip, {127, 0, 0, 1}}
        ]
    ),
    {ok, {_Address, Port}} = inet:sockname(Listener),
    Parent = self(),
    Server = spawn(fun() ->
        {ok, Socket} = gen_tcp:accept(Listener),
        ok = receive_request_headers(Socket, <<>>),
        Closed = ServerAction(Socket),
        catch gen_tcp:close(Socket),
        Parent ! {server_done, self(), Closed}
    end),
    Result = vestibule_public_http_transport:request(
        get,
        [{"host", "example.test"}, {"connection", "close"}],
        <<>>,
        http,
        <<"example.test">>,
        {some, Port},
        <<"/resource">>,
        none,
        {127, 0, 0, 1},
        Limit,
        Timeout
    ),
    catch gen_tcp:close(Listener),
    Closed =
        receive
            {server_done, Server, Value} -> Value
        after 2000 ->
            false
        end,
    {Result, Closed}.

receive_request_headers(Socket, Buffer) ->
    case binary:match(Buffer, <<"\r\n\r\n">>) of
        nomatch ->
            case gen_tcp:recv(Socket, 0, 1000) of
                {ok, Data} ->
                    receive_request_headers(
                        Socket,
                        <<Buffer/binary, Data/binary>>
                    );
                {error, Reason} ->
                    {error, Reason}
            end;
        _ ->
            ok
    end.

peer_closed(Socket) ->
    case gen_tcp:recv(Socket, 0, 1000) of
        {error, closed} -> true;
        _ -> false
    end.

oversized_error({error, {response_too_large, Reason}}, Detail) ->
    binary:match(Reason, <<"exceeds limit of 16 bytes">>) =/= nomatch
        andalso binary:match(Reason, Detail) =/= nomatch;
oversized_error(_, _) ->
    false.

response_error({error, {response_error, Reason}}, Detail) ->
    binary:match(Reason, Detail) =/= nomatch;
response_error(_, _) ->
    false.

request_budget_error({error, {network_failure, Reason}}, Detail) ->
    binary:match(Reason, Detail) =/= nomatch;
request_budget_error(_, _) ->
    false.

unsafe_target({error, {unsafe_target, _Reason}}) -> true;
unsafe_target(_) -> false.

admission_full({error, {network_failure, Reason}}) ->
    binary:match(Reason, <<"Too many public HTTP requests">>) =/= nomatch;
admission_full(_) ->
    false.

request_timeout({error, {network_failure, Reason}}) ->
    binary:match(Reason, <<"timed out">>) =/= nomatch;
request_timeout(_) ->
    false.

request(Path) ->
    {request, get, [], <<>>, https, <<"provider.example">>, none, Path, none}.

success_transport() ->
    fun(_, _, _, _, _, _, _, _, _, _, _) -> {ok, {200, [], <<>>}} end.

collect_started(0, Workers) ->
    Workers;
collect_started(Remaining, Workers) ->
    receive
        {transport_started, Worker} ->
            collect_started(Remaining - 1, [Worker | Workers])
    after 3000 ->
        Workers
    end.

collect_done([]) ->
    true;
collect_done(Callers) ->
    receive
        {request_done, Caller, {ok, {response, 200, [], <<>>}}} ->
            collect_done(lists:delete(Caller, Callers));
        {request_done, _Caller, _Result} ->
            false
    after 3000 ->
        false
    end.

restore_env(Name, false) ->
    os:unsetenv(Name);
restore_env(Name, Value) ->
    os:putenv(Name, Value).

ensure_admission_server() ->
    Resolver = fun(_) -> {ok, [{8, 8, 8, 8}]} end,
    {ok, {response, 200, [], <<>>}} =
        vestibule_public_http_ffi:send_with(
            request(<<"/initialize-admission">>),
            16,
            Resolver,
            success_transport(),
            1000
        ),
    ok.

admission_timeout_while_suspended(Server) ->
    Parent = self(),
    Resolver = fun(_) -> {ok, [{8, 8, 8, 8}]} end,
    Caller = spawn(fun() ->
        Result = vestibule_public_http_ffi:send_with(
            request(<<"/suspended-admission">>),
            16,
            Resolver,
            success_transport(),
            1000
        ),
        Parent ! {suspended_admission_result, self(), Result},
        receive
            finish -> ok
        end
    end),
    Result =
        receive
            {suspended_admission_result, Caller, Value} -> Value
        after 2000 ->
            timeout
        end,
    {message_queue_len, QueueLength} =
        process_info(Server, message_queue_len),
    {
        request_budget_error(Result, <<"admission control did not respond">>),
        QueueLength >= 2,
        Caller
    }.

barrier(Server) ->
    Reference = make_ref(),
    Server ! {barrier, self(), Reference},
    receive
        {Reference, ready} -> ok
    after 1000 ->
        timeout
    end.

find_coordinator([Pid | Rest], Excluded) ->
    case Pid =:= Excluded of
        true -> find_coordinator(Rest, Excluded);
        false -> Pid
    end;
find_coordinator([], _Excluded) ->
    none.
