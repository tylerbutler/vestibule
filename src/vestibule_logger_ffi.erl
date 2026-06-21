-module(vestibule_logger_ffi).
-export([log/2]).

log(Level, Fields) ->
    logger:log(level(Level), maps:from_list([{key(Key), Value} || {Key, Value} <- Fields])),
    nil.

level(<<"debug">>) -> debug;
level(<<"info">>) -> info;
level(<<"warning">>) -> warning;
level(<<"error">>) -> error;
level(_) -> debug.

key(<<"event">>) -> event;
key(<<"phase">>) -> phase;
key(<<"outcome">>) -> outcome;
key(<<"provider">>) -> provider;
key(<<"transport">>) -> transport;
key(<<"endpoint">>) -> endpoint;
key(<<"status">>) -> status;
key(<<"error_category">>) -> error_category;
key(<<"scope_count">>) -> scope_count;
key(<<"has_refresh_token">>) -> has_refresh_token;
key(<<"has_id_token">>) -> has_id_token;
key(<<"secure_cookie">>) -> secure_cookie;
key(Other) -> Other.
