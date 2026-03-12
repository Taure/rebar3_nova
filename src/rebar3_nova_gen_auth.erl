-module(rebar3_nova_gen_auth).

-export([init/1, do/1, format_error/1]).

-define(PROVIDER, gen_auth).
-define(DEPS, [{default, compile}]).

-spec init(rebar_state:t()) -> {ok, rebar_state:t()}.
init(State) ->
    Provider = providers:create([
            {name, ?PROVIDER},
            {module, ?MODULE},
            {namespace, nova},
            {bare, true},
            {deps, ?DEPS},
            {example, "rebar3 nova gen_auth"},
            {opts, []},
            {short_desc, "Generate Nova authentication controllers"},
            {desc,
                "Generates Nova controllers and security module for email/password auth.\n\n"
                "Requires 'rebar3 kura gen_auth' to be run first to generate\n"
                "the Kura schemas, migration, and accounts context.\n\n"
                "Generated files:\n"
                "  src/<app>_auth.erl                          (security callback)\n"
                "  src/controllers/<app>_session_controller.erl\n"
                "  src/controllers/<app>_registration_controller.erl\n"
                "  src/controllers/<app>_user_controller.erl\n"
                "  test/<app>_auth_SUITE.erl\n"}
    ]),
    {ok, rebar_state:add_provider(State, Provider)}.

-spec do(rebar_state:t()) -> {ok, rebar_state:t()} | {error, string()}.
do(State) ->
    AppName = rebar3_nova_utils:get_app_name(State),
    AppDir = rebar3_nova_utils:get_app_dir(State),
    App = atom_to_list(AppName),
    generate_auth(App, AppDir),
    generate_session_controller(App, AppDir),
    generate_registration_controller(App, AppDir),
    generate_user_controller(App, AppDir),
    generate_test_suite(App, AppDir),
    print_instructions(App),
    {ok, State}.

-spec format_error(any()) -> iolist().
format_error(Reason) ->
    io_lib:format("~p", [Reason]).

%%======================================================================
%% Auth security module
%%======================================================================

generate_auth(App, AppDir) ->
    Mod = App ++ "_auth",
    Accounts = App ++ "_accounts",
    FileName = filename:join([AppDir, "src", Mod ++ ".erl"]),
    Content = [
        "-module(", Mod, ").\n\n"
        "-export([require_authenticated/1]).\n\n"
        "require_authenticated(Req) ->\n"
        "    case nova_session:get(Req, <<\"session_token\">>) of\n"
        "        {ok, Token} ->\n"
        "            case ", Accounts, ":get_user_by_session_token(Token) of\n"
        "                {ok, User} ->\n"
        "                    {true, User};\n"
        "                _ ->\n"
        "                    unauthorized()\n"
        "            end;\n"
        "        _ ->\n"
        "            unauthorized()\n"
        "    end.\n\n"
        "unauthorized() ->\n"
        "    Body = thoas:encode(#{<<\"error\">> => <<\"unauthorized\">>}),\n"
        "    {false, 401, #{<<\"content-type\">> => <<\"application/json\">>}, Body}.\n"
    ],
    rebar3_nova_utils:write_file_if_not_exists(FileName, Content).

%%======================================================================
%% Session controller
%%======================================================================

generate_session_controller(App, AppDir) ->
    Mod = App ++ "_session_controller",
    Accounts = App ++ "_accounts",
    FileName = filename:join([AppDir, "src", "controllers", Mod ++ ".erl"]),
    Content = [
        "-module(", Mod, ").\n\n"
        "-export([create/1, delete/1]).\n\n"
        "create(Req) ->\n"
        "    #{<<\"email\">> := Email, <<\"password\">> := Password} = maps:get(json, Req),\n"
        "    case ", Accounts, ":get_user_by_email_and_password(Email, Password) of\n"
        "        {ok, User} ->\n"
        "            {ok, Token} = ", Accounts, ":generate_session_token(User),\n"
        "            ok = nova_session:set(Req, <<\"session_token\">>, Token),\n"
        "            {json, #{<<\"user\">> => ", Accounts, ":user_to_json(User)}};\n"
        "        {error, _} ->\n"
        "            {json, 401, #{}, #{<<\"error\">> => <<\"invalid email or password\">>}}\n"
        "    end.\n\n"
        "delete(Req) ->\n"
        "    case nova_session:get(Req, <<\"session_token\">>) of\n"
        "        {ok, Token} ->\n"
        "            ", Accounts, ":delete_session_token(Token);\n"
        "        _ ->\n"
        "            ok\n"
        "    end,\n"
        "    nova_session:delete(Req, <<\"session_token\">>),\n"
        "    {status, 204}.\n"
    ],
    rebar3_nova_utils:write_file_if_not_exists(FileName, Content).

%%======================================================================
%% Registration controller
%%======================================================================

generate_registration_controller(App, AppDir) ->
    Mod = App ++ "_registration_controller",
    Accounts = App ++ "_accounts",
    FileName = filename:join([AppDir, "src", "controllers", Mod ++ ".erl"]),
    Content = [
        "-module(", Mod, ").\n\n"
        "-export([create/1]).\n\n"
        "create(Req) ->\n"
        "    Params = maps:get(json, Req),\n"
        "    case ", Accounts, ":register_user(Params) of\n"
        "        {ok, User} ->\n"
        "            {ok, Token} = ", Accounts, ":generate_session_token(User),\n"
        "            ok = nova_session:set(Req, <<\"session_token\">>, Token),\n"
        "            {json, 201, #{}, #{<<\"user\">> => ", Accounts, ":user_to_json(User)}};\n"
        "        {error, CS} ->\n"
        "            {json, 422, #{}, #{<<\"errors\">> => ", Accounts, ":format_errors(CS)}}\n"
        "    end.\n"
    ],
    rebar3_nova_utils:write_file_if_not_exists(FileName, Content).

%%======================================================================
%% User controller
%%======================================================================

generate_user_controller(App, AppDir) ->
    Mod = App ++ "_user_controller",
    Accounts = App ++ "_accounts",
    FileName = filename:join([AppDir, "src", "controllers", Mod ++ ".erl"]),
    Content = [
        "-module(", Mod, ").\n\n"
        "-export([show/1, update_password/1, update_email/1]).\n\n"
        "show(Req) ->\n"
        "    User = maps:get(auth_data, Req),\n"
        "    {json, #{<<\"user\">> => ", Accounts, ":user_to_json(User)}}.\n\n"
        "update_password(Req) ->\n"
        "    User = maps:get(auth_data, Req),\n"
        "    #{<<\"current_password\">> := CurrentPassword} = maps:get(json, Req),\n"
        "    NewParams = maps:get(json, Req),\n"
        "    case ", Accounts, ":change_user_password(User, CurrentPassword, NewParams) of\n"
        "        {ok, UpdatedUser} ->\n"
        "            {ok, Token} = ", Accounts, ":generate_session_token(UpdatedUser),\n"
        "            ok = nova_session:set(Req, <<\"session_token\">>, Token),\n"
        "            {json, #{<<\"user\">> => ", Accounts, ":user_to_json(UpdatedUser)}};\n"
        "        {error, invalid_password} ->\n"
        "            {json, 401, #{}, #{<<\"error\">> => <<\"invalid current password\">>}};\n"
        "        {error, CS} ->\n"
        "            {json, 422, #{}, #{<<\"errors\">> => ", Accounts, ":format_errors(CS)}}\n"
        "    end.\n\n"
        "update_email(Req) ->\n"
        "    User = maps:get(auth_data, Req),\n"
        "    #{<<\"current_password\">> := CurrentPassword} = maps:get(json, Req),\n"
        "    NewParams = maps:get(json, Req),\n"
        "    case ", Accounts, ":change_user_email(User, CurrentPassword, NewParams) of\n"
        "        {ok, UpdatedUser} ->\n"
        "            {ok, Token} = ", Accounts, ":generate_session_token(UpdatedUser),\n"
        "            ok = nova_session:set(Req, <<\"session_token\">>, Token),\n"
        "            {json, #{<<\"user\">> => ", Accounts, ":user_to_json(UpdatedUser)}};\n"
        "        {error, invalid_password} ->\n"
        "            {json, 401, #{}, #{<<\"error\">> => <<\"invalid current password\">>}};\n"
        "        {error, CS} ->\n"
        "            {json, 422, #{}, #{<<\"errors\">> => ", Accounts, ":format_errors(CS)}}\n"
        "    end.\n"
    ],
    rebar3_nova_utils:write_file_if_not_exists(FileName, Content).

%%======================================================================
%% Test suite
%%======================================================================

generate_test_suite(App, AppDir) ->
    Suite = App ++ "_auth_SUITE",
    FileName = filename:join([AppDir, "test", Suite ++ ".erl"]),
    Content = [
        "-module(", Suite, ").\n"
        "-include_lib(\"common_test/include/ct.hrl\").\n\n"
        "-export([all/0, init_per_suite/1, end_per_suite/1,\n"
        "         init_per_testcase/2, end_per_testcase/2]).\n"
        "-export([\n"
        "    test_register/1,\n"
        "    test_register_invalid/1,\n"
        "    test_login/1,\n"
        "    test_login_invalid/1,\n"
        "    test_logout/1,\n"
        "    test_get_current_user/1,\n"
        "    test_unauthorized/1,\n"
        "    test_update_password/1,\n"
        "    test_update_email/1\n"
        "]).\n\n"
        "-define(BASE_URL, \"http://localhost:8080\").\n\n"
        "all() ->\n"
        "    [test_register, test_register_invalid, test_login, test_login_invalid,\n"
        "     test_logout, test_get_current_user, test_unauthorized,\n"
        "     test_update_password, test_update_email].\n\n"
        "init_per_suite(Config) ->\n"
        "    application:ensure_all_started(inets),\n"
        "    application:ensure_all_started(ssl),\n"
        "    application:ensure_all_started(", App, "),\n"
        "    Config.\n\n"
        "end_per_suite(_Config) ->\n"
        "    application:stop(", App, "),\n"
        "    ok.\n\n"
        "init_per_testcase(_TestCase, Config) ->\n"
        "    Config.\n\n"
        "end_per_testcase(_TestCase, _Config) ->\n"
        "    ok.\n\n"
        "%%----------------------------------------------------------------------\n"
        "%% Registration\n"
        "%%----------------------------------------------------------------------\n\n"
        "test_register(_Config) ->\n"
        "    Body = encode(#{<<\"email\">> => <<\"register@example.com\">>,\n"
        "                    <<\"password\">> => <<\"password123456\">>,\n"
        "                    <<\"password_confirmation\">> => <<\"password123456\">>}),\n"
        "    {ok, {{_, 201, _}, _, RespBody}} =\n"
        "        httpc:request(post,\n"
        "            {?BASE_URL ++ \"/api/register\", [], \"application/json\", Body},\n"
        "            [], []),\n"
        "    #{<<\"user\">> := #{<<\"id\">> := _, <<\"email\">> := <<\"register@example.com\">>}} =\n"
        "        decode(RespBody).\n\n"
        "test_register_invalid(_Config) ->\n"
        "    %% Missing password\n"
        "    Body1 = encode(#{<<\"email\">> => <<\"invalid@example.com\">>}),\n"
        "    {ok, {{_, 422, _}, _, _}} =\n"
        "        httpc:request(post,\n"
        "            {?BASE_URL ++ \"/api/register\", [], \"application/json\", Body1},\n"
        "            [], []),\n"
        "    %% Short password\n"
        "    Body2 = encode(#{<<\"email\">> => <<\"invalid@example.com\">>,\n"
        "                     <<\"password\">> => <<\"short\">>,\n"
        "                     <<\"password_confirmation\">> => <<\"short\">>}),\n"
        "    {ok, {{_, 422, _}, _, _}} =\n"
        "        httpc:request(post,\n"
        "            {?BASE_URL ++ \"/api/register\", [], \"application/json\", Body2},\n"
        "            [], []).\n\n"
        "%%----------------------------------------------------------------------\n"
        "%% Login / Logout\n"
        "%%----------------------------------------------------------------------\n\n"
        "test_login(_Config) ->\n"
        "    register_user(<<\"login@example.com\">>, <<\"password123456\">>),\n"
        "    Body = encode(#{<<\"email\">> => <<\"login@example.com\">>,\n"
        "                    <<\"password\">> => <<\"password123456\">>}),\n"
        "    {ok, {{_, 200, _}, _, RespBody}} =\n"
        "        httpc:request(post,\n"
        "            {?BASE_URL ++ \"/api/login\", [], \"application/json\", Body},\n"
        "            [], []),\n"
        "    #{<<\"user\">> := #{<<\"email\">> := <<\"login@example.com\">>}} =\n"
        "        decode(RespBody).\n\n"
        "test_login_invalid(_Config) ->\n"
        "    Body = encode(#{<<\"email\">> => <<\"nobody@example.com\">>,\n"
        "                    <<\"password\">> => <<\"wrongpassword1\">>}),\n"
        "    {ok, {{_, 401, _}, _, _}} =\n"
        "        httpc:request(post,\n"
        "            {?BASE_URL ++ \"/api/login\", [], \"application/json\", Body},\n"
        "            [], []).\n\n"
        "test_logout(_Config) ->\n"
        "    Cookie = register_and_login(<<\"logout@example.com\">>, <<\"password123456\">>),\n"
        "    {ok, {{_, 204, _}, _, _}} =\n"
        "        httpc:request(delete,\n"
        "            {?BASE_URL ++ \"/api/logout\", [{\"Cookie\", Cookie}]},\n"
        "            [], []).\n\n"
        "%%----------------------------------------------------------------------\n"
        "%% Current user\n"
        "%%----------------------------------------------------------------------\n\n"
        "test_get_current_user(_Config) ->\n"
        "    Cookie = register_and_login(<<\"me@example.com\">>, <<\"password123456\">>),\n"
        "    {ok, {{_, 200, _}, _, RespBody}} =\n"
        "        httpc:request(get,\n"
        "            {?BASE_URL ++ \"/api/me\", [{\"Cookie\", Cookie}]},\n"
        "            [], []),\n"
        "    #{<<\"user\">> := #{<<\"email\">> := <<\"me@example.com\">>}} =\n"
        "        decode(RespBody).\n\n"
        "test_unauthorized(_Config) ->\n"
        "    {ok, {{_, 401, _}, _, _}} =\n"
        "        httpc:request(get, {?BASE_URL ++ \"/api/me\", []}, [], []).\n\n"
        "%%----------------------------------------------------------------------\n"
        "%% Password & email update\n"
        "%%----------------------------------------------------------------------\n\n"
        "test_update_password(_Config) ->\n"
        "    Cookie = register_and_login(<<\"pwchange@example.com\">>, <<\"password123456\">>),\n"
        "    Body = encode(#{<<\"current_password\">> => <<\"password123456\">>,\n"
        "                    <<\"password\">> => <<\"newpassword12345\">>,\n"
        "                    <<\"password_confirmation\">> => <<\"newpassword12345\">>}),\n"
        "    {ok, {{_, 200, _}, _, _}} =\n"
        "        httpc:request(put,\n"
        "            {?BASE_URL ++ \"/api/me/password\",\n"
        "             [{\"Cookie\", Cookie}], \"application/json\", Body},\n"
        "            [], []).\n\n"
        "test_update_email(_Config) ->\n"
        "    Cookie = register_and_login(<<\"emailchange@example.com\">>, <<\"password123456\">>),\n"
        "    Body = encode(#{<<\"current_password\">> => <<\"password123456\">>,\n"
        "                    <<\"email\">> => <<\"newemail@example.com\">>}),\n"
        "    {ok, {{_, 200, _}, _, _}} =\n"
        "        httpc:request(put,\n"
        "            {?BASE_URL ++ \"/api/me/email\",\n"
        "             [{\"Cookie\", Cookie}], \"application/json\", Body},\n"
        "            [], []).\n\n"
        "%%----------------------------------------------------------------------\n"
        "%% Helpers\n"
        "%%----------------------------------------------------------------------\n\n"
        "register_user(Email, Password) ->\n"
        "    Body = encode(#{<<\"email\">> => Email, <<\"password\">> => Password,\n"
        "                    <<\"password_confirmation\">> => Password}),\n"
        "    {ok, {{_, 201, _}, _, _}} =\n"
        "        httpc:request(post,\n"
        "            {?BASE_URL ++ \"/api/register\", [], \"application/json\", Body},\n"
        "            [], []).\n\n"
        "register_and_login(Email, Password) ->\n"
        "    Body = encode(#{<<\"email\">> => Email, <<\"password\">> => Password,\n"
        "                    <<\"password_confirmation\">> => Password}),\n"
        "    {ok, {{_, 201, _}, Headers, _}} =\n"
        "        httpc:request(post,\n"
        "            {?BASE_URL ++ \"/api/register\", [], \"application/json\", Body},\n"
        "            [], []),\n"
        "    extract_cookie(Headers).\n\n"
        "extract_cookie(Headers) ->\n"
        "    case lists:keyfind(\"set-cookie\", 1, Headers) of\n"
        "        {_, Cookie} -> Cookie;\n"
        "        false -> \"\"\n"
        "    end.\n\n"
        "encode(Map) ->\n"
        "    binary_to_list(thoas:encode(Map)).\n\n"
        "decode(Body) ->\n"
        "    {ok, Json} = thoas:decode(list_to_binary(Body)),\n"
        "    Json.\n"
    ],
    rebar3_nova_utils:write_file_if_not_exists(FileName, Content).

%%======================================================================
%% Print instructions
%%======================================================================

print_instructions(App) ->
    AuthMod = App ++ "_auth",
    SessionCtrl = App ++ "_session_controller",
    RegCtrl = App ++ "_registration_controller",
    UserCtrl = App ++ "_user_controller",
    rebar_api:info("~n==> Nova auth controllers generated successfully!~n", []),
    rebar_api:info("Make sure you've run 'rebar3 kura gen_auth' first.~n~n", []),
    rebar_api:info("Add these routes to your router:~n", []),
    rebar_api:info("   %% Public routes~n", []),
    rebar_api:info("   #{prefix => <<\"/api\">>,~n"
                   "     security => false,~n"
                   "     plugins => [{pre_request, nova_request_plugin,~n"
                   "                  #{decode_json_body => true}}],~n"
                   "     routes => [~n"
                   "       {<<\"/register\">>, fun ~s:create/1, #{methods => [post]}},~n"
                   "       {<<\"/login\">>, fun ~s:create/1, #{methods => [post]}}~n"
                   "     ]}~n", [RegCtrl, SessionCtrl]),
    rebar_api:info("   %% Protected routes~n", []),
    rebar_api:info("   #{prefix => <<\"/api\">>,~n"
                   "     security => fun ~s:require_authenticated/1,~n"
                   "     plugins => [{pre_request, nova_request_plugin,~n"
                   "                  #{decode_json_body => true}}],~n"
                   "     routes => [~n"
                   "       {<<\"/logout\">>, fun ~s:delete/1, #{methods => [delete]}},~n"
                   "       {<<\"/me\">>, fun ~s:show/1, #{methods => [get]}},~n"
                   "       {<<\"/me/password\">>, fun ~s:update_password/1, #{methods => [put]}},~n"
                   "       {<<\"/me/email\">>, fun ~s:update_email/1, #{methods => [put]}}~n"
                   "     ]}~n", [AuthMod, SessionCtrl, UserCtrl, UserCtrl, UserCtrl]).
