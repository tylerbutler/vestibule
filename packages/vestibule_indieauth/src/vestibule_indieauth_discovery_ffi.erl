-module(vestibule_indieauth_discovery_ffi).

-export([catch_parser_crash/1]).

catch_parser_crash(Run) ->
    try Run() of
        {ok, Value} -> {ok, Value};
        {error, _Reason} -> {error, nil}
    catch
        error:{case_clause, _Value} -> {error, nil}
    end.
