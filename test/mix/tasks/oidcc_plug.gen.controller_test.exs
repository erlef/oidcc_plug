defmodule OidccPlug.Gen.ControllerTest do
  use ExUnit.Case, async: true

  import Igniter.Test

  alias Igniter.Project.Formatter

  setup do
    igniter_project_starter =
      phx_test_project()
      |> Formatter.import_dep(:phoenix)
      |> Igniter.compose_task("igniter.add_extension", ["phoenix"])
      |> apply_igniter!()

    {:ok, igniter_project_starter: igniter_project_starter}
  end

  test "creates controller", %{igniter_project_starter: igniter_project_starter} do
    igniter_project_starter
    |> Igniter.compose_task("oidcc_plug.gen.controller", [
      "--name",
      "TestWeb.AuthController",
      "--provider",
      "Test.Provider",
      "--issuer",
      "https://accounts.google.com"
    ])
    |> assert_has_patch("config/config.exs", ~S"""
        ...|
    8  8   |import Config
    9  9   |
      10 + |config :test, TestWeb.AuthController, provider: Test.Provider
      11 + |
    10 12   |config :test,
    11 13   |  ecto_repos: [Test.Repo],
        ...|
    """)
    |> assert_has_patch("config/runtime.exs", """
    1 1   |import Config
    2 2   |
      3 + |config :test, TestWeb.AuthController,
      4 + |  client_id: System.fetch_env!("TEST_PROVIDER_CLIENT_ID"),
      5 + |  client_secret: System.fetch_env!("TEST_PROVIDER_CLIENT_SECRET")
      6 + |
      7 + |config :test, Test.Provider,
      8 + |  issuer: System.get_env("TEST_PROVIDER_ISSUER", "https://accounts.google.com")
      9 + |
    """)
    |> assert_has_patch("lib/test/application.ex", """
         ...|
     9  9   |  def start(_type, _args) do
    10 10   |    children = [
       11 + |      {Oidcc.ProviderConfiguration.Worker,
       12 + |       %{name: Test.Provider, issuer: Application.fetch_env!(:test, Test.Provider)[:issuer]}},
    11 13   |      TestWeb.Telemetry,
    12 14   |      Test.Repo,
         ...|
    """)
    |> assert_has_patch("lib/test/test_web/auth_html.ex", """
    1 |defmodule Test.TestWeb.AuthHTML do
    2 |  defmodule Test.TestWeb.AuthHTML do
    3 |    use TestWeb, :html
    4 |    embed_templates("auth_html/*")
    5 |  end
    6 |end
    7 |
    """)
    |> assert_has_patch("lib/test_web/controllers/auth_controller.ex", """
    1  |defmodule TestWeb.AuthController do
    2  |  use TestWeb, :controller
    3  |
    4  |  plug(
    5  |    Oidcc.Plug.Authorize,
    6  |    [
    7  |      provider: Application.compile_env(:test, [__MODULE__, :provider]),
    8  |      client_id: &__MODULE__.client_id/0,
    9  |      client_secret: &__MODULE__.client_secret/0,
    10 |      redirect_uri: &__MODULE__.callback_uri/0
    11 |    ]
    12 |    when action in [:authorize]
    13 |  )
    14 |
    15 |  plug(
    16 |    Oidcc.Plug.AuthorizationCallback,
    17 |    [
    18 |      provider: Application.compile_env(:test, [__MODULE__, :provider]),
    19 |      client_id: &__MODULE__.client_id/0,
    20 |      client_secret: &__MODULE__.client_secret/0,
    21 |      redirect_uri: &__MODULE__.callback_uri/0
    22 |    ]
    23 |    when action in [:callback]
    24 |  )
    25 |
    26 |  def authorize(conn, _params) do
    27 |    conn
    28 |  end
    29 |
    30 |  def callback(
    31 |        %Plug.Conn{private: %{Oidcc.Plug.AuthorizationCallback => {:ok, {_token, userinfo}}}} =
    32 |          conn,
    33 |        params
    34 |      ) do
    35 |    conn
    36 |    |> put_session("oidcc_claims", userinfo)
    37 |    |> redirect(
    38 |      to:
    39 |        case params[:state] do
    40 |          nil -> "/"
    41 |          state -> state
    42 |        end
    43 |    )
    44 |  end
    45 |
    46 |  def callback(
    47 |        %Plug.Conn{private: %{Oidcc.Plug.AuthorizationCallback => {:error, reason}}} = conn,
    48 |        _params
    49 |      ) do
    50 |    conn |> put_status(400) |> render(:error, reason: reason)
    51 |  end
    52 |
    53 |  @doc false
    54 |  def client_id do
    55 |    Application.fetch_env!(:test, __MODULE__)[:client_id]
    56 |  end
    57 |
    58 |  @doc false
    59 |  def client_secret do
    60 |    Application.fetch_env!(:test, __MODULE__)[:client_secret]
    61 |  end
    62 |
    63 |  @doc false
    64 |  def callback_uri do
    65 |    url(~p"/auth/callback")
    66 |  end
    67 |end
    68 |
    """)
    |> assert_has_patch("lib/test_web/controllers/auth_html/error.html.heex", """
    1 |<p>error:</p>
    2 |
    3 |<pre><%= inspect(@reason, pretty: true) %></pre>
    4 |
    """)
    |> assert_has_patch("lib/test_web/controllers/page_html/home.html.heex", """
           ...|
    222 222   |</div>
    223 223   |
        224 + |
        225 + |<div class="px-4 py-10 sm:px-6 sm:py-28 lg:px-8 xl:px-28 xl:py-32">
        226 + |  <div class="mx-auto max-w-xl lg:mx-0">
        227 + |    <div class="group -mx-2 -my-0.5 inline-flex items-center gap-3 px-2 py-0.5">
        228 + |      <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="h-4 w-4">
        229 + |        <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 6a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0zM4.501 20.118a7.5 7.5 0 0114.998 0A17.933 17.933 0 0112 21.75c-2.676 0-5.216-.584-7.499-1.632z" />
        230 + |      </svg>
        231 + |
        232 + |      <%= case Plug.Conn.get_session(@conn, "oidcc_claims") do %>
        233 + |        <% nil -> %>
        234 + |          <a href={ ~p"/auth/authorize" }>
        235 + |            Log In
        236 + |          </a>
        237 + |        <% %{"sub" => sub} -> %>
        238 + |          <span class="text-base text-zinc-600">Logged in as <%= sub %></span>
        239 + |      <% end %>
        240 + |    </div>
        241 + |  </div>
        242 + |</div>
        243 + |
    """)
    |> assert_has_patch("lib/test_web/router.ex", """
         ...|
    15 15   |  end
    16 16   |
       17 + |  scope "/auth", TestWeb do
       18 + |    pipe_through([:browser])
       19 + |
       20 + |    get("/authorize", AuthController, :authorize)
       21 + |    get("/callback", AuthController, :callback)
       22 + |    post("/callback", AuthController, :callback)
       23 + |  end
       24 + |
    17 25   |  scope "/", TestWeb do
    18 26   |    pipe_through(:browser)
         ...|
    """)
  end
end
