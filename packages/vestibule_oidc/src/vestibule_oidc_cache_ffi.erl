-module(vestibule_oidc_cache_ffi).

-export([get/2, put/2]).

-define(SERVER, vestibule_oidc_jwks_cache).
-define(MAX_ENTRIES, 64).

get(Key, TtlSeconds) ->
    call({get, Key, TtlSeconds}).

put(Key, Value) ->
    call({put, Key, Value}),
    nil.

call(Request) ->
    Server = ensure_server(),
    Reference = make_ref(),
    Server ! {call, self(), Reference, Request},
    receive
        {Reference, Reply} -> Reply
    after 5000 ->
        case Request of
            {get, _, _} -> {error, nil};
            {put, _, _} -> nil
        end
    end.

ensure_server() ->
    case whereis(?SERVER) of
        undefined ->
            Candidate = spawn(fun() -> loop(#{} ) end),
            case catch register(?SERVER, Candidate) of
                true -> Candidate;
                _ ->
                    exit(Candidate, kill),
                    whereis(?SERVER)
            end;
        Server ->
            Server
    end.

loop(Cache) ->
    receive
        {call, Caller, Reference, {get, Key, TtlSeconds}} ->
            Now = erlang:monotonic_time(second),
            case maps:find(Key, Cache) of
                {ok, {InsertedAt, Value}} when Now - InsertedAt =< TtlSeconds ->
                    Caller ! {Reference, {ok, Value}},
                    loop(Cache);
                {ok, _Expired} ->
                    Caller ! {Reference, {error, nil}},
                    loop(maps:remove(Key, Cache));
                error ->
                    Caller ! {Reference, {error, nil}},
                    loop(Cache)
            end;
        {call, Caller, Reference, {put, Key, Value}} ->
            Now = erlang:monotonic_time(second),
            Updated = maps:put(Key, {Now, Value}, Cache),
            Bounded = evict_if_needed(Updated),
            Caller ! {Reference, nil},
            loop(Bounded)
    end.

evict_if_needed(Cache) when map_size(Cache) =< ?MAX_ENTRIES ->
    Cache;
evict_if_needed(Cache) ->
    [{OldestKey, _} | _] =
        lists:sort(
          fun({_KeyA, {TimeA, _}}, {_KeyB, {TimeB, _}}) ->
                  TimeA =< TimeB
          end,
          maps:to_list(Cache)),
    maps:remove(OldestKey, Cache).
