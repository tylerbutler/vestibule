-module(vestibule_public_http_transport).
-export([request/11]).

-define(MAX_HEADER_BYTES, 65536).
-define(READ_CHUNK_BYTES, 8192).

request(
    Method,
    Headers,
    Body,
    Scheme,
    Host,
    Port,
    Path,
    Query,
    Address,
    BodyLimit,
    Timeout
) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    case connect(Scheme, Host, Address, effective_port(Scheme, Port), Deadline) of
        {ok, Socket} ->
            try
                case send_request(
                    Socket,
                    Method,
                    Headers,
                    Body,
                    Path,
                    Query,
                    Deadline
                ) of
                    ok -> receive_response(Socket, Method, BodyLimit, Deadline);
                    {error, Reason} -> {error, {transport, Reason}}
                end
            after
                close(Socket)
            end;
        {error, Reason} ->
            {error, {transport, Reason}}
    end.

connect(http, _Host, Address, Port, Deadline) ->
    case remaining(Deadline) of
        {ok, Timeout} ->
            connect_tcp(Address, Port, Timeout);
        {error, Reason} ->
            {error, Reason}
    end;
connect(https, Host, Address, Port, Deadline) ->
    case application:ensure_all_started(ssl) of
        {ok, _Started} ->
            case remaining(Deadline) of
                {ok, Timeout} ->
                    connect_tls(Host, Address, Port, Timeout);
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, format_error(ssl_start, Reason)}
    end;
connect(_, _Host, _Address, _Port, _Deadline) ->
    {error, <<"Unsupported HTTP scheme">>}.

connect_tcp(Address, Port, Timeout) ->
    case gen_tcp:connect(
        Address,
        Port,
        [
            binary,
            address_family(Address),
            {active, false},
            {packet, line},
            {packet_size, ?MAX_HEADER_BYTES},
            {buffer, ?READ_CHUNK_BYTES},
            {recbuf, ?READ_CHUNK_BYTES},
            {nodelay, true}
        ],
        Timeout
    ) of
        {ok, Socket} -> {ok, {tcp, Socket}};
        {error, Reason} -> {error, format_error(connect, Reason)}
    end.

connect_tls(Host, Address, Port, Timeout) ->
    TlsOptions = [
        binary,
        address_family(Address),
        {active, false},
        {packet, line},
        {packet_size, ?MAX_HEADER_BYTES},
        {buffer, ?READ_CHUNK_BYTES},
        {recbuf, ?READ_CHUNK_BYTES}
        | tls_options(Host)
    ],
    case ssl:connect(Address, Port, TlsOptions, Timeout) of
        {ok, Socket} -> {ok, {tls, Socket}};
        {error, Reason} -> {error, format_error(tls_connect, Reason)}
    end.

send_request(Socket, Method, Headers0, Body, Path, Query, Deadline) ->
    case request_method(Method) of
        {ok, MethodText, HasBody} ->
            Target = request_target(Path, Query),
            case valid_request_target(Target) of
                true ->
                    Headers = request_headers(Headers0, Body, HasBody),
                    Data = [
                        MethodText,
                        <<" ">>,
                        Target,
                        <<" HTTP/1.1\r\n">>,
                        [[Name, <<": ">>, Value, <<"\r\n">>] ||
                            {Name, Value} <- Headers],
                        <<"\r\n">>,
                        case HasBody of
                            true -> Body;
                            false -> <<>>
                        end
                    ],
                    socket_send(Socket, Data, Deadline);
                false ->
                    {error, <<"HTTP request target contains invalid characters">>}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

request_method(get) -> {ok, <<"GET">>, false};
request_method(head) -> {ok, <<"HEAD">>, false};
request_method(options) -> {ok, <<"OPTIONS">>, false};
request_method(post) -> {ok, <<"POST">>, true};
request_method(put) -> {ok, <<"PUT">>, true};
request_method(patch) -> {ok, <<"PATCH">>, true};
request_method(delete) -> {ok, <<"DELETE">>, true};
request_method(trace) -> {ok, <<"TRACE">>, true};
request_method(connect) -> {ok, <<"CONNECT">>, true};
request_method(_) -> {error, <<"Unsupported HTTP method">>}.

request_target(<<>>, Query) ->
    request_target(<<"/">>, Query);
request_target(Path, none) ->
    Path;
request_target(Path, {some, Query}) ->
    <<Path/binary, "?", Query/binary>>.

valid_request_target(<<>>) ->
    false;
valid_request_target(Target) ->
    lists:all(
        fun(Byte) -> Byte >= 16#21 andalso Byte =/= 16#7f end,
        binary_to_list(Target)
    ).

request_headers(Headers, Body, true) ->
    [
        {"content-length", integer_to_list(byte_size(Body))}
        | remove_framing_headers(Headers)
    ];
request_headers(Headers, _Body, false) ->
    remove_framing_headers(Headers).

remove_framing_headers(Headers) ->
    [
        {Name, Value}
     || {Name, Value} <- Headers,
        string:lowercase(Name) =/= "content-length",
        string:lowercase(Name) =/= "transfer-encoding"
    ].

receive_response(Socket, Method, BodyLimit, Deadline) ->
    receive_response(Socket, Method, BodyLimit, Deadline, 0).

receive_response(Socket, Method, BodyLimit, Deadline, HeaderBytes) ->
    case read_response_head(Socket, Deadline, HeaderBytes) of
        {ok, Status, _Headers, NewHeaderBytes}
        when Status >= 100, Status < 200 ->
            receive_response(
                Socket,
                Method,
                BodyLimit,
                Deadline,
                NewHeaderBytes
            );
        {ok, Status, Headers, NewHeaderBytes} ->
            case read_response_body(
                Socket,
                Method,
                Status,
                Headers,
                BodyLimit,
                Deadline,
                NewHeaderBytes
            ) of
                {ok, ResponseBody, FinalHeaders} ->
                    {ok, {Status, FinalHeaders, ResponseBody}};
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

read_response_head(Socket, Deadline, HeaderBytes) ->
    case recv_line(Socket, Deadline) of
        {ok, StatusLine} ->
            NewBytes = HeaderBytes + byte_size(StatusLine),
            case NewBytes =< ?MAX_HEADER_BYTES of
                false ->
                    response_too_large(
                        <<"HTTP response headers exceed 65536 bytes">>
                    );
                true ->
                    case parse_status_line(StatusLine) of
                        {ok, Status} ->
                            read_headers(
                                Socket,
                                Deadline,
                                NewBytes,
                                Status,
                                []
                            );
                        {error, Reason} ->
                            {error, {response_error, Reason}}
                    end
            end;
        {error, packet_too_large} ->
            response_too_large(<<"HTTP response headers exceed 65536 bytes">>);
        {error, Reason} ->
            {error, {transport, Reason}}
    end.

read_headers(Socket, Deadline, HeaderBytes, Status, Headers) ->
    case recv_line(Socket, Deadline) of
        {ok, Line} ->
            NewBytes = HeaderBytes + byte_size(Line),
            case NewBytes =< ?MAX_HEADER_BYTES of
                false ->
                    response_too_large(
                        <<"HTTP response headers exceed 65536 bytes">>
                    );
                true ->
                    case Line of
                        <<"\r\n">> ->
                            {ok, Status, lists:reverse(Headers), NewBytes};
                        _ ->
                            case parse_header(Line) of
                                {ok, Header} ->
                                    read_headers(
                                        Socket,
                                        Deadline,
                                        NewBytes,
                                        Status,
                                        [Header | Headers]
                                    );
                                {error, Reason} ->
                                    {error, {response_error, Reason}}
                            end
                    end
            end;
        {error, packet_too_large} ->
            response_too_large(<<"HTTP response headers exceed 65536 bytes">>);
        {error, Reason} ->
            {error, {transport, Reason}}
    end.

parse_status_line(Line) ->
    case strip_crlf(Line) of
        {ok, WithoutCrLf} ->
            case binary:split(WithoutCrLf, <<" ">>, [global, trim_all]) of
                [Version, StatusText | _]
                when
                    (Version =:= <<"HTTP/1.0">> orelse
                        Version =:= <<"HTTP/1.1">>) andalso
                        byte_size(StatusText) =:= 3
                ->
                    case all_decimal(StatusText) of
                        true -> {ok, binary_to_integer(StatusText)};
                        false -> {error, <<"Invalid HTTP response status">>}
                    end;
                _ ->
                    {error, <<"Invalid HTTP response status line">>}
            end;
        error ->
            {error, <<"HTTP response line did not end with CRLF">>}
    end.

parse_header(Line) ->
    case strip_crlf(Line) of
        {ok, <<First, _/binary>>} when First =:= $\s; First =:= $\t ->
            {error, <<"Folded HTTP response headers are not supported">>};
        {ok, WithoutCrLf} ->
            case binary:match(WithoutCrLf, <<":">>) of
                {Position, 1} ->
                    Name = binary:part(WithoutCrLf, 0, Position),
                    ValueStart = Position + 1,
                    ValueSize = byte_size(WithoutCrLf) - ValueStart,
                    Value0 = binary:part(
                        WithoutCrLf,
                        ValueStart,
                        ValueSize
                    ),
                    Value = trim_ows(Value0),
                    case
                        valid_header_name(Name) andalso
                            valid_header_value(Value) andalso
                            valid_utf8(Value)
                    of
                        true -> {ok, {Name, Value}};
                        false ->
                            {error, <<"HTTP response contains an invalid header">>}
                    end;
                nomatch ->
                    {error, <<"HTTP response contains an invalid header">>}
            end;
        error ->
            {error, <<"HTTP response line did not end with CRLF">>}
    end.

read_response_body(
    Socket,
    Method,
    Status,
    Headers,
    Limit,
    Deadline,
    HeaderBytes
) ->
    case response_has_no_body(Method, Status) of
        true ->
            {ok, <<>>, Headers};
        false ->
            case transfer_encoding(Headers) of
                chunked ->
                    read_chunked_body(
                        Socket,
                        Limit,
                        Deadline,
                        HeaderBytes,
                        [],
                        0,
                        Headers
                    );
                unsupported ->
                    {error,
                        {response_error,
                            <<"Unsupported HTTP response transfer-encoding">>}};
                none ->
                    case content_length(Headers) of
                        {ok, Length} when Length > Limit ->
                            response_too_large(content_length_error(Limit, Length));
                        {ok, Length} ->
                            case set_packet(Socket, raw) of
                                ok ->
                                    read_fixed_body(
                                        Socket,
                                        Length,
                                        Deadline,
                                        [],
                                        Headers
                                    );
                                {error, Reason} ->
                                    {error, {transport, Reason}}
                            end;
                        none ->
                            case set_packet(Socket, raw) of
                                ok ->
                                    read_close_delimited_body(
                                        Socket,
                                        Limit,
                                        Deadline,
                                        [],
                                        0,
                                        Headers
                                    );
                                {error, Reason} ->
                                    {error, {transport, Reason}}
                            end;
                        {error, Reason} ->
                            {error, {response_error, Reason}}
                    end
            end
    end.

response_has_no_body(head, _Status) -> true;
response_has_no_body(_Method, Status) when Status =:= 204; Status =:= 304 ->
    true;
response_has_no_body(_, _) -> false.

transfer_encoding(Headers) ->
    Values = header_values(Headers, <<"transfer-encoding">>),
    case Values of
        [] ->
            none;
        _ ->
            Tokens = lists:append([
                [
                    string:lowercase(trim_ows(Token))
                 || Token <- binary:split(Value, <<",">>, [global])
                ]
             || Value <- Values
            ]),
            case Tokens of
                [] -> unsupported;
                _ ->
                    case lists:last(Tokens) of
                        <<"chunked">> -> chunked;
                        _ -> unsupported
                    end
            end
    end.

content_length(Headers) ->
    Values0 = header_values(Headers, <<"content-length">>),
    Values = lists:append([
        [trim_ows(Value) || Value <- binary:split(Header, <<",">>, [global])]
     || Header <- Values0
    ]),
    case Values of
        [] ->
            none;
        [First | Rest] ->
            case parse_decimal(First) of
                {ok, Length} ->
                    case lists:all(fun(Value) -> Value =:= First end, Rest) of
                        true -> {ok, Length};
                        false ->
                            {error,
                                <<"HTTP response has conflicting Content-Length headers">>}
                    end;
                error ->
                    {error, <<"HTTP response has an invalid Content-Length">>}
            end
    end.

read_fixed_body(_Socket, Remaining, _Deadline, Parts, Headers)
when Remaining =:= 0 ->
    {ok, iolist_to_binary(lists:reverse(Parts)), Headers};
read_fixed_body(Socket, Remaining, Deadline, Parts, Headers) ->
    Wanted = erlang:min(Remaining, ?READ_CHUNK_BYTES),
    case socket_recv(Socket, Wanted, Deadline) of
        {ok, Data} ->
            read_fixed_body(
                Socket,
                Remaining - byte_size(Data),
                Deadline,
                [Data | Parts],
                Headers
            );
        {error, Reason} ->
            {error, {response_error, Reason}}
    end.

read_close_delimited_body(
    Socket,
    Limit,
    Deadline,
    Parts,
    Received,
    Headers
) ->
    case socket_recv(Socket, 0, Deadline) of
        {ok, Data} when Received + byte_size(Data) > Limit ->
            response_too_large(streaming_error(Limit, <<"close-delimited">>));
        {ok, Data} ->
            read_close_delimited_body(
                Socket,
                Limit,
                Deadline,
                [Data | Parts],
                Received + byte_size(Data),
                Headers
            );
        {error, closed} ->
            {ok, iolist_to_binary(lists:reverse(Parts)), Headers};
        {error, Reason} ->
            {error, {response_error, Reason}}
    end.

read_chunked_body(
    Socket,
    Limit,
    Deadline,
    HeaderBytes,
    Parts,
    Received,
    Headers
) ->
    case recv_line(Socket, Deadline) of
        {ok, Line} when HeaderBytes + byte_size(Line) =< ?MAX_HEADER_BYTES ->
            case parse_chunk_size(Line) of
                {ok, 0} ->
                    read_trailers(
                        Socket,
                        Deadline,
                        HeaderBytes + byte_size(Line),
                        Parts,
                        [],
                        Headers
                    );
                {ok, Size} when Received + Size > Limit ->
                    response_too_large(streaming_error(Limit, <<"chunked">>));
                {ok, Size} ->
                    case set_packet(Socket, raw) of
                        ok ->
                            case read_exact(Socket, Size, Deadline, []) of
                                {ok, Chunk} ->
                                    case read_exact(Socket, 2, Deadline, []) of
                                        {ok, <<"\r\n">>} ->
                                            case set_packet(Socket, line) of
                                                ok ->
                                                    read_chunked_body(
                                                        Socket,
                                                        Limit,
                                                        Deadline,
                                                        HeaderBytes +
                                                            byte_size(Line),
                                                        [Chunk | Parts],
                                                        Received + Size,
                                                        Headers
                                                    );
                                                {error, Reason} ->
                                                    {error, {transport, Reason}}
                                            end;
                                        {ok, _} ->
                                            {error,
                                                {response_error,
                                                    <<"Invalid chunk terminator">>}};
                                        {error, Reason} ->
                                            {error, {response_error, Reason}}
                                    end;
                                {error, Reason} ->
                                    {error, {response_error, Reason}}
                            end;
                        {error, Reason} ->
                            {error, {transport, Reason}}
                    end;
                {error, Reason} ->
                    {error, {response_error, Reason}}
            end;
        {ok, _Line} ->
            response_too_large(<<"HTTP response headers exceed 65536 bytes">>);
        {error, packet_too_large} ->
            response_too_large(<<"HTTP response headers exceed 65536 bytes">>);
        {error, Reason} ->
            {error, {response_error, Reason}}
    end.

read_trailers(
    Socket,
    Deadline,
    HeaderBytes,
    Parts,
    Trailers,
    Headers
) ->
    case recv_line(Socket, Deadline) of
        {ok, Line} ->
            NewBytes = HeaderBytes + byte_size(Line),
            case NewBytes =< ?MAX_HEADER_BYTES of
                false ->
                    response_too_large(
                        <<"HTTP response headers exceed 65536 bytes">>
                    );
                true ->
                    case Line of
                        <<"\r\n">> ->
                            {ok,
                                iolist_to_binary(lists:reverse(Parts)),
                                Headers ++ lists:reverse(Trailers)};
                        _ ->
                            case parse_header(Line) of
                                {ok, Trailer} ->
                                    read_trailers(
                                        Socket,
                                        Deadline,
                                        NewBytes,
                                        Parts,
                                        [Trailer | Trailers],
                                        Headers
                                    );
                                {error, Reason} ->
                                    {error, {response_error, Reason}}
                            end
                    end
            end;
        {error, packet_too_large} ->
            response_too_large(<<"HTTP response headers exceed 65536 bytes">>);
        {error, Reason} ->
            {error, {response_error, Reason}}
    end.

read_exact(_Socket, 0, _Deadline, Parts) ->
    {ok, iolist_to_binary(lists:reverse(Parts))};
read_exact(Socket, Remaining, Deadline, Parts) ->
    Wanted = erlang:min(Remaining, ?READ_CHUNK_BYTES),
    case socket_recv(Socket, Wanted, Deadline) of
        {ok, Data} ->
            read_exact(
                Socket,
                Remaining - byte_size(Data),
                Deadline,
                [Data | Parts]
            );
        {error, Reason} ->
            {error, Reason}
    end.

parse_chunk_size(Line) ->
    case strip_crlf(Line) of
        {ok, WithoutCrLf} ->
            [SizeText0 | _] = binary:split(WithoutCrLf, <<";">>, [global]),
            SizeText = trim_ows(SizeText0),
            case byte_size(SizeText) > 0 andalso all_hexadecimal(SizeText) of
                true ->
                    try {ok, binary_to_integer(SizeText, 16)}
                    catch
                        error:badarg ->
                            {error, <<"Invalid HTTP chunk size">>}
                    end;
                false ->
                    {error, <<"Invalid HTTP chunk size">>}
            end;
        error ->
            {error, <<"HTTP chunk line did not end with CRLF">>}
    end.

recv_line(Socket, Deadline) ->
    socket_recv(Socket, 0, Deadline).

socket_send({tcp, Socket}, Data, Deadline) ->
    case remaining(Deadline) of
        {ok, Timeout} ->
            case inet:setopts(Socket, [{send_timeout, Timeout}]) of
                ok ->
                    case gen_tcp:send(Socket, Data) of
                        ok -> ok;
                        {error, Reason} ->
                            {error, format_error(send, Reason)}
                    end;
                {error, Reason} ->
                    {error, format_error(socket_options, Reason)}
            end;
        Error ->
            Error
    end;
socket_send({tls, Socket}, Data, Deadline) ->
    case remaining(Deadline) of
        {ok, Timeout} ->
            case ssl:setopts(Socket, [{send_timeout, Timeout}]) of
                ok ->
                    case ssl:send(Socket, Data) of
                        ok -> ok;
                        {error, Reason} ->
                            {error, format_error(send, Reason)}
                    end;
                {error, Reason} ->
                    {error, format_error(socket_options, Reason)}
            end;
        Error ->
            Error
    end.

socket_recv({tcp, Socket}, Length, Deadline) ->
    case remaining(Deadline) of
        {ok, Timeout} ->
            normalize_recv(gen_tcp:recv(Socket, Length, Timeout));
        Error ->
            Error
    end;
socket_recv({tls, Socket}, Length, Deadline) ->
    case remaining(Deadline) of
        {ok, Timeout} ->
            normalize_recv(ssl:recv(Socket, Length, Timeout));
        Error ->
            Error
    end.

normalize_recv({ok, Data}) ->
    {ok, Data};
normalize_recv({error, timeout}) ->
    {error, <<"HTTP request timed out">>};
normalize_recv({error, closed}) ->
    {error, closed};
normalize_recv({error, emsgsize}) ->
    {error, packet_too_large};
normalize_recv({error, Reason}) ->
    {error, format_error(receive_response, Reason)}.

set_packet({tcp, Socket}, Packet) ->
    case inet:setopts(Socket, [{packet, Packet}]) of
        ok -> ok;
        {error, Reason} -> {error, format_error(socket_options, Reason)}
    end;
set_packet({tls, Socket}, Packet) ->
    case ssl:setopts(Socket, [{packet, Packet}]) of
        ok -> ok;
        {error, Reason} -> {error, format_error(socket_options, Reason)}
    end.

close({tcp, Socket}) ->
    catch gen_tcp:close(Socket),
    ok;
close({tls, Socket}) ->
    catch ssl:close(Socket),
    ok.

remaining(Deadline) ->
    Value = Deadline - erlang:monotonic_time(millisecond),
    case Value > 0 of
        true -> {ok, Value};
        false -> {error, <<"HTTP request timed out">>}
    end.

effective_port(http, none) -> 80;
effective_port(https, none) -> 443;
effective_port(_Scheme, {some, Port}) -> Port.

address_family(Address) when tuple_size(Address) =:= 8 -> inet6;
address_family(_Address) -> inet.

tls_options(Host) ->
    NormalizedHost = strip_trailing_dot(strip_brackets(Host)),
    Base = httpc:ssl_verify_host_options(true),
    case host_is_ip_literal(NormalizedHost) of
        true -> Base;
        false ->
            [
                {server_name_indication, binary_to_list(NormalizedHost)}
                | Base
            ]
    end.

host_is_ip_literal(Host) ->
    case inet:parse_address(binary_to_list(strip_brackets(Host))) of
        {ok, _} -> true;
        {error, _} -> false
    end.

strip_brackets(<<"[", Rest/binary>>) ->
    case byte_size(Rest) of
        0 -> Rest;
        Size ->
            case binary:last(Rest) of
                $] -> binary:part(Rest, 0, Size - 1);
                _ -> <<"[", Rest/binary>>
            end
    end;
strip_brackets(Host) ->
    Host.

strip_trailing_dot(Host) ->
    case byte_size(Host) of
        0 -> Host;
        Size ->
            case binary:last(Host) of
                $. -> binary:part(Host, 0, Size - 1);
                _ -> Host
            end
    end.

header_values(Headers, Target) ->
    [
        Value
     || {Name, Value} <- Headers,
        string:lowercase(Name) =:= Target
    ].

strip_crlf(Binary) ->
    Size = byte_size(Binary),
    case Size >= 2 andalso binary:part(Binary, Size - 2, 2) =:= <<"\r\n">> of
        true -> {ok, binary:part(Binary, 0, Size - 2)};
        false -> error
    end.

trim_ows(Binary) ->
    trim_ows_right(trim_ows_left(Binary)).

trim_ows_left(<<Byte, Rest/binary>>) when Byte =:= $\s; Byte =:= $\t ->
    trim_ows_left(Rest);
trim_ows_left(Binary) ->
    Binary.

trim_ows_right(Binary) ->
    case byte_size(Binary) of
        0 ->
            Binary;
        Size ->
            case binary:last(Binary) of
                Byte when Byte =:= $\s; Byte =:= $\t ->
                    trim_ows_right(binary:part(Binary, 0, Size - 1));
                _ ->
                    Binary
            end
    end.

parse_decimal(<<>>) ->
    error;
parse_decimal(Binary) ->
    case all_decimal(Binary) of
        true ->
            try {ok, binary_to_integer(Binary)}
            catch
                error:badarg -> error
            end;
        false ->
            error
    end.

all_decimal(Binary) ->
    lists:all(
        fun(Byte) -> Byte >= $0 andalso Byte =< $9 end,
        binary_to_list(Binary)
    ).

all_hexadecimal(Binary) ->
    lists:all(
        fun(Byte) ->
            (Byte >= $0 andalso Byte =< $9)
                orelse (Byte >= $a andalso Byte =< $f)
                orelse (Byte >= $A andalso Byte =< $F)
        end,
        binary_to_list(Binary)
    ).

valid_header_name(<<>>) ->
    false;
valid_header_name(Name) ->
    lists:all(fun is_header_name_character/1, binary_to_list(Name)).

is_header_name_character(Character) ->
    (Character >= $a andalso Character =< $z)
        orelse (Character >= $A andalso Character =< $Z)
        orelse (Character >= $0 andalso Character =< $9)
        orelse lists:member(Character, "!#$%&'*+-.^_`|~").

valid_header_value(Value) ->
    lists:all(
        fun(Character) ->
            Character =:= $\t
                orelse (Character >= 32 andalso Character =/= 127)
        end,
        binary_to_list(Value)
    ).

valid_utf8(Value) ->
    is_binary(unicode:characters_to_binary(Value, utf8, utf8)).

content_length_error(Limit, Declared) ->
    iolist_to_binary(
        io_lib:format(
            "HTTP response body exceeds limit of ~B bytes "
            "(Content-Length: ~B)",
            [Limit, Declared]
        )
    ).

streaming_error(Limit, Framing) ->
    iolist_to_binary(
        io_lib:format(
            "HTTP response body exceeds limit of ~B bytes "
            "while streaming ~s response",
            [Limit, Framing]
        )
    ).

response_too_large(Reason) ->
    {error, {response_too_large, Reason}}.

format_error(Class, Reason) ->
    unicode:characters_to_binary(io_lib:format("~p: ~p", [Class, Reason])).
