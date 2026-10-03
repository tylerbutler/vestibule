-module(vestibule_secret_test_ffi).

-export([format_term/1]).

format_term(Term) ->
    unicode:characters_to_binary(io_lib:format("~p", [Term])).
