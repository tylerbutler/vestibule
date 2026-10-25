-module(vestibule_secret_test_ffi).

-export([format_crash_report/1, format_term/1]).

format_crash_report(Term) ->
    unicode:characters_to_binary(
        io_lib:format(
            "~p",
            [#{reason => simulated_crash, process_state => Term}]
        )
    ).

format_term(Term) ->
    unicode:characters_to_binary(io_lib:format("~p", [Term])).
