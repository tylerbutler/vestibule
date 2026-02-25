-module(vestibule_apple_id_token_cache_ffi).
-export([create_table/1, insert/3, lookup/2, delete_key/2]).

create_table(Name) ->
    Atom = binary_to_atom(Name, utf8),
    case ets:whereis(Atom) of
        undefined ->
            ets:new(Atom, [set, public, named_table]),
            nil;
        _Ref ->
            nil
    end.

insert(Name, Key, Value) ->
    Atom = binary_to_atom(Name, utf8),
    ets:insert(Atom, {Key, Value}),
    nil.

lookup(Name, Key) ->
    Atom = binary_to_atom(Name, utf8),
    case ets:lookup(Atom, Key) of
        [{_Key, Value}] -> {ok, Value};
        [] -> {error, nil}
    end.

delete_key(Name, Key) ->
    Atom = binary_to_atom(Name, utf8),
    ets:delete(Atom, Key),
    nil.
