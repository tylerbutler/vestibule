-module(vestibule_public_http_test_ffi).
-export([
    oversized_content_length/0,
    chunked_overflow/0,
    close_delimited_overflow/0,
    just_under_limit/0,
    close_delimited_success/0,
    invalid_utf8_header/0,
    concurrent_cleanup/0,
    response_timeout/0
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
