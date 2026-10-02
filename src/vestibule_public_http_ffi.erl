-module(vestibule_public_http_ffi).
-export([
    validate_host/1,
    validate_host_format/1,
    validate_addresses/2,
    send/1,
    send/2,
    send_with/5,
    admission_limit/0,
    address_is_global/1
]).

-define(TIMEOUT, 30000).
-define(DEFAULT_BODY_LIMIT, 262144).
-define(MAX_BODY_LIMIT, 1048576).
-define(MAX_REQUEST_URL_BYTES, 8192).
-define(MAX_REQUEST_HEADER_BYTES, 65536).
-define(MAX_REQUEST_BODY_BYTES, 1048576).
-define(MAX_IN_FLIGHT, 64).
-define(ADMISSION_SERVER, vestibule_public_http_admission).

validate_host(Host) when is_binary(Host) ->
    case resolve_public(Host) of
        {ok, _Addresses} -> {ok, nil};
        {error, Reason} -> {error, Reason}
    end.

validate_host_format(Host0) when is_binary(Host0) ->
    Host = strip_brackets(strip_trailing_dot(Host0)),
    case blocked_hostname(Host) of
        true ->
            {error, <<"Host is not publicly routable: ", Host0/binary>>};
        false ->
            case inet:parse_address(binary_to_list(Host)) of
                {ok, Address} ->
                    case is_global(Address) of
                        true -> {ok, nil};
                        false ->
                            {error,
                                <<"Host is not publicly routable: ",
                                    Host0/binary>>}
                    end;
                {error, _} ->
                    {ok, nil}
            end
    end.

address_is_global(Address) when is_binary(Address) ->
    case inet:parse_address(binary_to_list(strip_brackets(Address))) of
        {ok, Parsed} -> is_global(Parsed);
        {error, _} -> false
    end.

validate_addresses(Host, Addresses) when is_binary(Host), is_list(Addresses) ->
    case parse_addresses(Addresses, []) of
        {ok, Parsed} -> validate_resolved_addresses(Host, Parsed);
        {error, Reason} -> {error, Reason}
    end.

send(Request) ->
    send(Request, ?DEFAULT_BODY_LIMIT).

send(Request = {request, _, _, _, _, _, _, _, _}, BodyLimit)
when is_integer(BodyLimit), BodyLimit > 0, BodyLimit =< ?MAX_BODY_LIMIT ->
    send_with(
        Request,
        BodyLimit,
        fun resolve_addresses/1,
        fun vestibule_public_http_transport:request/11,
        ?TIMEOUT
    );
send(_, _) ->
    {error, {network_failure, <<"Invalid HTTP request or response limit">>}}.

send_with(
    Request = {request, _, _, _, _, _, _, _, _},
    BodyLimit,
    Resolver,
    Transport,
    Timeout
)
when
    is_integer(BodyLimit),
    BodyLimit > 0,
    BodyLimit =< ?MAX_BODY_LIMIT,
    is_function(Resolver, 1),
    is_function(Transport, 11),
    is_integer(Timeout),
    Timeout > 0
->
    case validate_request_budget(Request) of
        ok ->
            case acquire_admission() of
                {ok, Permit} ->
                    send_admitted(
                        Request,
                        BodyLimit,
                        Resolver,
                        Transport,
                        Timeout,
                        Permit
                    );
                full ->
                    {error,
                        {network_failure,
                            <<"Too many public HTTP requests are in flight">>}};
                {error, Reason} ->
                    {error, {network_failure, Reason}}
            end;
        {error, Reason} ->
            {error, {network_failure, Reason}}
    end;
send_with(_, _, _, _, _) ->
    {error, {network_failure, <<"Invalid HTTP request or response limit">>}}.

admission_limit() ->
    ?MAX_IN_FLIGHT.

send_admitted(Request, BodyLimit, Resolver, Transport, Timeout, Permit) ->
    Caller = self(),
    Reference = make_ref(),
    {Coordinator, Monitor} = spawn_monitor(fun() ->
        CallerMonitor = erlang:monitor(process, Caller),
        receive
            start ->
                coordinate_request(
                    Caller,
                    Reference,
                    Request,
                    BodyLimit,
                    Resolver,
                    Transport,
                    Timeout,
                    Permit,
                    CallerMonitor
                );
            {'DOWN', CallerMonitor, process, Caller, _Reason} ->
                ok
        after Timeout ->
            ok
        end
    end),
    case transfer_admission(Permit, Coordinator) of
        ok ->
            Coordinator ! start,
            receive
                {Reference, Result} ->
                    erlang:demonitor(Monitor, [flush]),
                    Result;
                {'DOWN', Monitor, process, Coordinator, Reason} ->
                    {error,
                        {network_failure,
                            format_error(httpc_coordinator, Reason)}}
            end;
        {error, Reason} ->
            exit(Coordinator, kill),
            receive
                {'DOWN', Monitor, process, Coordinator, _} -> ok
            end,
            {error, {network_failure, Reason}}
    end.

validate_request_budget(
    {request, _Method, Headers, Body, Scheme, Host, Port, Path, Query}
) when
    is_list(Headers),
    is_binary(Body),
    is_atom(Scheme),
    is_binary(Host),
    is_binary(Path)
->
    UrlBytes = request_url_bytes(Scheme, Host, Port, Path, Query),
    HeaderBytes = request_header_bytes(
        [
            {<<"host">>, host_header(Host, Scheme, Port)},
            {<<"connection">>, <<"close">>},
            {<<"content-length">>, integer_to_binary(byte_size(Body))}
            | Headers
        ],
        0
    ),
    case {
        UrlBytes =< ?MAX_REQUEST_URL_BYTES,
        HeaderBytes,
        byte_size(Body) =< ?MAX_REQUEST_BODY_BYTES
    } of
        {false, _, _} ->
            {error, <<"HTTP request URL exceeds 8192 bytes">>};
        {true, overflow, _} ->
            {error, <<"HTTP request headers exceed 65536 bytes">>};
        {true, _, false} ->
            {error, <<"HTTP request body exceeds 1048576 bytes">>};
        {true, _, true} ->
            ok
    end;
validate_request_budget(_) ->
    {error, <<"Invalid HTTP request">>}.

request_url_bytes(Scheme, Host, Port, Path, Query) ->
    byte_size(atom_to_binary(Scheme, utf8))
        + 3
        + byte_size(Host)
        + port_bytes(Port)
        + byte_size(Path)
        + query_bytes(Query).

port_bytes(none) -> 0;
port_bytes({some, Port}) when is_integer(Port) ->
    1 + byte_size(integer_to_binary(Port));
port_bytes(_) -> ?MAX_REQUEST_URL_BYTES + 1.

query_bytes(none) -> 0;
query_bytes({some, Query}) when is_binary(Query) -> 1 + byte_size(Query);
query_bytes(_) -> ?MAX_REQUEST_URL_BYTES + 1.

request_header_bytes([], Bytes) ->
    Bytes;
request_header_bytes([{Name, Value} | Rest], Bytes)
when is_binary(Name), is_binary(Value) ->
    NewBytes = Bytes + byte_size(Name) + byte_size(Value) + 4,
    case NewBytes =< ?MAX_REQUEST_HEADER_BYTES of
        true -> request_header_bytes(Rest, NewBytes);
        false -> overflow
    end;
request_header_bytes(_, _) ->
    overflow.

acquire_admission() ->
    Server = admission_server(),
    Reference = erlang:alias([reply]),
    Monitor = erlang:monitor(process, Server),
    Server ! {acquire, self(), Reference},
    receive
        {Reference, Result} ->
            erlang:unalias(Reference),
            erlang:demonitor(Monitor, [flush]),
            case Result of
                {ok, Permit} -> {ok, {Server, Permit}};
                full -> full
            end;
        {'DOWN', Monitor, process, Server, _Reason} ->
            erlang:unalias(Reference),
            acquire_admission()
    after 1000 ->
        erlang:unalias(Reference),
        erlang:demonitor(Monitor, [flush]),
        Server ! {cancel, self(), Reference},
        {error, <<"Public HTTP admission control did not respond">>}
    end.

transfer_admission({Server, Permit}, NewOwner) ->
    Reference = erlang:alias([reply]),
    Monitor = erlang:monitor(process, Server),
    Server ! {transfer, self(), Reference, Permit, NewOwner},
    receive
        {Reference, transferred} ->
            erlang:unalias(Reference),
            erlang:demonitor(Monitor, [flush]),
            ok;
        {Reference, invalid_permit} ->
            erlang:unalias(Reference),
            erlang:demonitor(Monitor, [flush]),
            {error, <<"Public HTTP admission permit was lost">>};
        {'DOWN', Monitor, process, Server, _Reason} ->
            erlang:unalias(Reference),
            {error, <<"Public HTTP admission control stopped">>}
    after 1000 ->
        erlang:unalias(Reference),
        erlang:demonitor(Monitor, [flush]),
        {error, <<"Public HTTP admission control did not transfer permit">>}
    end.

release_admission({Server, Permit}) ->
    Reference = erlang:alias([reply]),
    Server ! {release, self(), Reference, Permit},
    receive
        {Reference, released} ->
            erlang:unalias(Reference),
            ok
    after 1000 ->
        erlang:unalias(Reference),
        ok
    end.

admission_server() ->
    case whereis(?ADMISSION_SERVER) of
        undefined ->
            Candidate = spawn(fun() -> admission_loop(#{}) end),
            try
                true = register(?ADMISSION_SERVER, Candidate),
                Candidate
            catch
                error:badarg ->
                    exit(Candidate, kill),
                    admission_server()
            end;
        Server ->
            Server
    end.

admission_loop(Permits) ->
    receive
        {acquire, Caller, Reference} when is_pid(Caller) ->
            case map_size(Permits) < ?MAX_IN_FLIGHT of
                true ->
                    Permit = Reference,
                    Monitor = erlang:monitor(process, Caller),
                    Reference ! {Reference, {ok, Permit}},
                    admission_loop(
                        maps:put(Permit, {Caller, Monitor}, Permits)
                    );
                false ->
                    Reference ! {Reference, full},
                    admission_loop(Permits)
            end;
        {cancel, Caller, Permit} when is_pid(Caller) ->
            admission_loop(remove_owned_permit(Permits, Permit, Caller));
        {transfer, Caller, Reference, Permit, NewOwner}
        when is_pid(Caller), is_pid(NewOwner) ->
            case maps:find(Permit, Permits) of
                {ok, {Caller, OldMonitor}} ->
                    erlang:demonitor(OldMonitor, [flush]),
                    NewMonitor = erlang:monitor(process, NewOwner),
                    Reference ! {Reference, transferred},
                    admission_loop(
                        maps:put(Permit, {NewOwner, NewMonitor}, Permits)
                    );
                _ ->
                    Reference ! {Reference, invalid_permit},
                    admission_loop(Permits)
            end;
        {release, Caller, Reference, Permit} when is_pid(Caller) ->
            case maps:take(Permit, Permits) of
                {{_Caller, Monitor}, Remaining} ->
                    erlang:demonitor(Monitor, [flush]),
                    Reference ! {Reference, released},
                    admission_loop(Remaining);
                error ->
                    Reference ! {Reference, released},
                    admission_loop(Permits)
            end;
        {barrier, Caller, Reference} when is_pid(Caller) ->
            Caller ! {Reference, ready},
            admission_loop(Permits);
        {'DOWN', Monitor, process, Caller, _Reason} ->
            admission_loop(remove_dead_permit(Permits, Caller, Monitor));
        _ ->
            admission_loop(Permits)
    end.

remove_dead_permit(Permits, Caller, Monitor) ->
    maps:filter(
        fun(_Permit, Entry) -> Entry =/= {Caller, Monitor} end,
        Permits
    ).

remove_owned_permit(Permits, Permit, Caller) ->
    case maps:find(Permit, Permits) of
        {ok, {Caller, Monitor}} ->
            erlang:demonitor(Monitor, [flush]),
            maps:remove(Permit, Permits);
        _ ->
            Permits
    end.

coordinate_request(
    Caller,
    Reference,
    Request,
    BodyLimit,
    Resolver,
    Transport,
    Timeout,
    Permit,
    CallerMonitor
) ->
    Coordinator = self(),
    {Worker, WorkerMonitor} = spawn_monitor(fun() ->
        process_flag(trap_exit, true),
        Coordinator ! {
            Reference,
            send_request(Request, BodyLimit, Resolver, Transport, Timeout)
        }
    end),
    receive
        {Reference, Result} ->
            erlang:demonitor(CallerMonitor, [flush]),
            erlang:demonitor(WorkerMonitor, [flush]),
            release_admission(Permit),
            Caller ! {Reference, Result};
        {'DOWN', CallerMonitor, process, Caller, _Reason} ->
            stop_worker(Worker, WorkerMonitor),
            release_admission(Permit);
        {'DOWN', WorkerMonitor, process, Worker, Reason} ->
            erlang:demonitor(CallerMonitor, [flush]),
            release_admission(Permit),
            Caller ! {
                Reference,
                {error,
                    {network_failure,
                        format_error(httpc_worker, Reason)}}
            }
    after Timeout ->
        erlang:demonitor(CallerMonitor, [flush]),
        stop_worker(Worker, WorkerMonitor),
        release_admission(Permit),
        Caller ! {
            Reference,
            {error, {network_failure, <<"HTTP request timed out">>}}
        }
    end.

stop_worker(Worker, WorkerMonitor) ->
    exit(Worker, kill),
    receive
        {'DOWN', WorkerMonitor, process, Worker, _Reason} -> ok
    end.

send_request(
    {request, Method, Headers, Body, Scheme, Host, Port, Path, Query},
    BodyLimit,
    Resolver,
    Transport,
    Timeout
) ->
    try
        case resolve_public(Host, Resolver) of
            {ok, Addresses = [_ | _]} ->
                send_pinned_addresses(
                    Addresses,
                    Method,
                    Headers,
                    Body,
                    Scheme,
                    Host,
                    Port,
                    Path,
                    Query,
                    BodyLimit,
                    Transport,
                    Timeout,
                    undefined
                );
            {ok, []} ->
                {error, {unsafe_target, <<"Host resolution returned no addresses">>}};
            {error, Reason} ->
                {error, {unsafe_target, Reason}}
        end
    catch
        Class:CaughtReason ->
            {error, {network_failure, format_error(Class, CaughtReason)}}
    end.

send_pinned_addresses(
    [],
    _Method,
    _Headers,
    _Body,
    _Scheme,
    _Host,
    _Port,
    _Path,
    _Query,
    _BodyLimit,
    _Transport,
    _Timeout,
    LastError
) ->
    LastError;
send_pinned_addresses(
    [Address | Rest],
    Method,
    Headers,
    Body,
    Scheme,
    Host,
    Port,
    Path,
    Query,
    BodyLimit,
    Transport,
    Timeout,
    _LastError
) ->
    case send_pinned(
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
        Transport,
        Timeout
    ) of
        Result = {ok, _} ->
            Result;
        Error = {error, {network_failure, _}} ->
            send_pinned_addresses(
                Rest,
                Method,
                Headers,
                Body,
                Scheme,
                Host,
                Port,
                Path,
                Query,
                BodyLimit,
                Transport,
                Timeout,
                Error
            );
        {error, {response_failure, Reason}} ->
            {error, {network_failure, Reason}}
    end.

resolve_public(Host0) ->
    resolve_public(Host0, fun resolve_addresses/1).

resolve_public(Host0, Resolver) ->
    Host = strip_brackets(strip_trailing_dot(Host0)),
    case blocked_hostname(Host) of
        true ->
            {error, <<"Host is not publicly routable: ", Host0/binary>>};
        false ->
            case Resolver(Host) of
                {ok, Addresses} ->
                    case validate_resolved_addresses(Host0, Addresses) of
                        {ok, nil} -> {ok, Addresses};
                        {error, Reason} -> {error, Reason}
                    end;
                {error, Reason} ->
                    {error,
                        <<"Could not resolve host ", Host0/binary, ": ",
                            Reason/binary>>}
            end
    end.

parse_addresses([], Parsed) ->
    {ok, lists:reverse(Parsed)};
parse_addresses([Address | Rest], Parsed) when is_binary(Address) ->
    case inet:parse_address(binary_to_list(strip_brackets(Address))) of
        {ok, Value} -> parse_addresses(Rest, [Value | Parsed]);
        {error, _} ->
            {error, <<"Invalid resolved address: ", Address/binary>>}
    end;
parse_addresses(_, _) ->
    {error, <<"Invalid resolved address list">>}.

validate_resolved_addresses(Host, []) ->
    {error, <<"Host resolution returned no addresses: ", Host/binary>>};
validate_resolved_addresses(Host, Addresses) ->
    case [Address || Address <- Addresses, not is_global(Address)] of
        [] -> {ok, nil};
        [Blocked | _] ->
            BlockedText = address_to_binary(Blocked),
            {error,
                <<"Host resolves to a non-public address: ",
                    Host/binary, " -> ", BlockedText/binary>>}
    end.

resolve_addresses(Host) ->
    HostList = binary_to_list(Host),
    case inet:parse_address(HostList) of
        {ok, Address} ->
            {ok, [Address]};
        {error, _} ->
            V4 = resolved_family(HostList, inet),
            V6 = resolved_family(HostList, inet6),
            Addresses = lists:usort(V4 ++ V6),
            case Addresses of
                [] ->
                    {error, resolution_error(HostList)};
                _ ->
                    {ok, Addresses}
            end
    end.

resolved_family(Host, Family) ->
    case inet:getaddrs(Host, Family) of
        {ok, Addresses} -> Addresses;
        {error, _} -> []
    end.

resolution_error(Host) ->
    V4Error = inet:getaddrs(Host, inet),
    V6Error = inet:getaddrs(Host, inet6),
    unicode:characters_to_binary(
        io_lib:format("IPv4 ~p; IPv6 ~p", [V4Error, V6Error])
    ).

blocked_hostname(Host) ->
    Normalized = string:lowercase(Host),
    Normalized =:= <<"localhost">>
        orelse binary_ends_with(Normalized, <<".localhost">>)
        orelse binary_ends_with(Normalized, <<".local">>).

send_pinned(
    Method,
    Headers0,
    Body,
    Scheme,
    Host,
    Port,
    Path,
    Query,
    Address,
    BodyLimit,
    Transport,
    Timeout
) ->
    case validate_headers(Headers0) of
        ok ->
            send_pinned_valid(
                Method,
                Headers0,
                Body,
                Scheme,
                Host,
                Port,
                Path,
                Query,
                Address,
                BodyLimit,
                Transport,
                Timeout
            );
        {error, Reason} ->
            {error, {network_failure, Reason}}
    end.

send_pinned_valid(
    Method,
    Headers0,
    Body,
    Scheme,
    Host,
    Port,
    Path,
    Query,
    Address,
    BodyLimit,
    Transport,
    Timeout
) ->
    HostHeader = host_header(Host, Scheme, Port),
    Headers = prepare_headers(
        set_header(
            set_header(Headers0, <<"host">>, HostHeader),
            <<"connection">>,
            <<"close">>
        )
    ),
    handle_response(
        Transport(
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
        )
    ).

validate_headers([]) ->
    ok;
validate_headers([{Name, Value} | Rest])
when is_binary(Name), is_binary(Value) ->
    case valid_header_name(Name) andalso valid_header_value(Value) of
        true -> validate_headers(Rest);
        false -> {error, <<"HTTP request contains an invalid header">>}
    end;
validate_headers(_) ->
    {error, <<"HTTP request contains an invalid header">>}.

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

handle_response({ok, {Status, ResponseHeaders, ResponseBody}}) ->
    case {
        response_headers_to_utf8(ResponseHeaders, []),
        unicode:characters_to_binary(ResponseBody, utf8, utf8)
    } of
        {{ok, Utf8Headers}, Utf8Body} when is_binary(Utf8Body) ->
            {ok, {response, Status, Utf8Headers, Utf8Body}};
        {{error, Reason}, _} ->
            {error, {response_failure, Reason}};
        {_, _} ->
            {error,
                {response_failure,
                    <<"HTTP response body was not valid UTF-8">>}}
    end;
handle_response({error, {response_too_large, Reason}}) ->
    {error, {response_failure, Reason}};
handle_response({error, {response_error, Reason}}) ->
    {error, {response_failure, Reason}};
handle_response({error, {transport, Reason}}) when is_binary(Reason) ->
    {error, {network_failure, Reason}};
handle_response({error, Reason}) ->
    {error, {network_failure, format_error(http_transport, Reason)}}.

response_headers_to_utf8([], Headers) ->
    {ok, lists:reverse(Headers)};
response_headers_to_utf8([{Name, Value} | Rest], Headers) ->
    case {
        unicode:characters_to_binary(Name, utf8, utf8),
        unicode:characters_to_binary(Value, utf8, utf8)
    } of
        {Utf8Name, Utf8Value}
        when is_binary(Utf8Name), is_binary(Utf8Value) ->
            response_headers_to_utf8(
                Rest,
                [{Utf8Name, Utf8Value} | Headers]
            );
        _ ->
            {error, <<"HTTP response headers were not valid UTF-8">>}
    end.

host_header(Host0, Scheme, Port) ->
    Host = strip_brackets(Host0),
    RenderedHost =
        case binary:match(Host, <<":">>) of
            nomatch -> Host;
            _ -> <<"[", Host/binary, "]">>
        end,
    case Port of
        none -> RenderedHost;
        {some, Value} ->
            case default_port(Scheme, Value) of
                true -> RenderedHost;
                false -> <<RenderedHost/binary, ":", (integer_to_binary(Value))/binary>>
            end
    end.

default_port(http, 80) -> true;
default_port(https, 443) -> true;
default_port(_, _) -> false.

prepare_headers(Headers) ->
    [{binary_to_list(Name), binary_to_list(Value)} || {Name, Value} <- Headers].

set_header(Headers, Name, Value) ->
    [{Name, Value} | [{K, V} || {K, V} <- Headers, string:lowercase(K) =/= Name]].

is_global(Address = {_A, _B, _C, _D}) ->
    ipv4_is_global(Address);
is_global(Address = {_A, _B, _C, _D, _E, _F, _G, _H}) ->
    case embedded_ipv4(Address) of
        {ok, Embedded} ->
            ipv4_is_global(Embedded);
        error ->
            ipv6_is_global(Address)
    end;
is_global(_) ->
    false.

%% Keep embedded IPv4 decisions aligned with the IANA IPv4 registry:
%% https://www.iana.org/assignments/iana-ipv4-special-registry/
ipv4_is_global({192, 0, 0, D}) ->
    D =:= 9 orelse D =:= 10;
ipv4_is_global({A, B, C, _D}) ->
    not (
        A =:= 0
        orelse A =:= 10
        orelse A =:= 127
        orelse (A =:= 100 andalso B >= 64 andalso B =< 127)
        orelse (A =:= 169 andalso B =:= 254)
        orelse (A =:= 172 andalso B >= 16 andalso B =< 31)
        orelse (A =:= 192 andalso B =:= 168)
        orelse (A =:= 192 andalso B =:= 0 andalso C =:= 2)
        orelse (A =:= 192 andalso B =:= 88 andalso C =:= 99)
        orelse (A =:= 198 andalso (B =:= 18 orelse B =:= 19))
        orelse (A =:= 198 andalso B =:= 51 andalso C =:= 100)
        orelse (A =:= 203 andalso B =:= 0 andalso C =:= 113)
        orelse A >= 224
    ).

%% The IANA IPv6 Special-Purpose Address Space registry marks 2001::/23
%% non-global unless a more-specific allocation says otherwise:
%% https://www.iana.org/assignments/iana-ipv6-special-registry/
ipv6_is_global(Address) ->
    case ipv6_in_prefix(Address, {16#2000, 0, 0, 0, 0, 0, 0, 0}, 3) of
        false ->
            false;
        true ->
            not ipv6_in_prefix(
                Address,
                {16#2001, 16#db8, 0, 0, 0, 0, 0, 0},
                32
            )
                andalso not ipv6_in_prefix(
                    Address,
                    {16#2002, 0, 0, 0, 0, 0, 0, 0},
                    16
                )
                andalso not ipv6_in_prefix(
                    Address,
                    {16#3fff, 0, 0, 0, 0, 0, 0, 0},
                    20
                )
                andalso (
                    not ipv6_in_prefix(
                        Address,
                        {16#2001, 0, 0, 0, 0, 0, 0, 0},
                        23
                    )
                    orelse ietf_protocol_assignment_is_global(Address)
                )
    end.

ietf_protocol_assignment_is_global({16#2001, 1, 0, 0, 0, 0, 0, D}) ->
    D >= 1 andalso D =< 3;
ietf_protocol_assignment_is_global(Address) ->
    %% ORCHIDv2 (2001:20::/28) is deliberately absent: RFC 7343 defines
    %% ORCHIDs as non-routable identifiers that must not appear in IPv6 headers.
    ipv6_in_prefix(Address, {16#2001, 3, 0, 0, 0, 0, 0, 0}, 32)
        orelse ipv6_in_prefix(
            Address,
            {16#2001, 4, 16#112, 0, 0, 0, 0, 0},
            48
        )
        orelse ipv6_in_prefix(
            Address,
            {16#2001, 16#30, 0, 0, 0, 0, 0, 0},
            28
        ).

ipv6_in_prefix(Address, Prefix, Length) ->
    Shift = 128 - Length,
    (ipv6_to_integer(Address) bsr Shift) =:=
        (ipv6_to_integer(Prefix) bsr Shift).

ipv6_to_integer({A, B, C, D, E, F, G, H}) ->
    (A bsl 112)
        bor (B bsl 96)
        bor (C bsl 80)
        bor (D bsl 64)
        bor (E bsl 48)
        bor (F bsl 32)
        bor (G bsl 16)
        bor H.

%% Normalize only IPv4-mapped addresses and RFC 6052's globally reachable
%% 64:ff9b::/96 translation prefix, then apply the IPv4 registry rules.
embedded_ipv4({0, 0, 0, 0, 0, 16#ffff, G, H}) ->
    {ok, words_to_ipv4(G, H)};
embedded_ipv4({16#64, 16#ff9b, 0, 0, 0, 0, G, H}) ->
    {ok, words_to_ipv4(G, H)};
embedded_ipv4(_) ->
    error.

words_to_ipv4(G, H) ->
    {G bsr 8, G band 16#ff, H bsr 8, H band 16#ff}.

address_to_binary(Address) ->
    unicode:characters_to_binary(inet:ntoa(Address)).

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

binary_ends_with(Binary, Suffix) ->
    BinarySize = byte_size(Binary),
    SuffixSize = byte_size(Suffix),
    BinarySize >= SuffixSize
        andalso binary:part(Binary, BinarySize - SuffixSize, SuffixSize) =:= Suffix.

format_error(Class, Reason) ->
    unicode:characters_to_binary(io_lib:format("~p: ~p", [Class, Reason])).
