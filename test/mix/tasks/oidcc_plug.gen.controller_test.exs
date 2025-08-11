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
       |import Config
       |
     + |config :test, TestWeb.AuthController, provider: Test.Provider
     + |
       |config :test,
       |  ecto_repos: [Test.Repo]
    ...|
    """)
    |> assert_has_patch("config/runtime.exs", """
      |import Config
      |
    + |config :test, TestWeb.AuthController,
    + |  client_id: System.fetch_env!("TEST_PROVIDER_CLIENT_ID"),
    + |  client_secret: System.fetch_env!("TEST_PROVIDER_CLIENT_SECRET")
    + |
    + |config :test, Test.Provider,
    + |  issuer: System.get_env("TEST_PROVIDER_ISSUER", "https://accounts.google.com")
    + |
    """)
    |> assert_has_patch("lib/test/application.ex", """
    ...|
       |  def start(_type, _args) do
       |    children = [
     + |      {Oidcc.ProviderConfiguration.Worker,
     + |       %{name: Test.Provider, issuer: Application.fetch_env!(:test, Test.Provider)[:issuer]}},
       |      TestWeb.Telemetry,
       |      Test.Repo,
    ...|
    """)
    |> assert_has_patch("lib/test/test_web/auth_html.ex", """
    |defmodule Test.TestWeb.AuthHTML do
    |  defmodule Test.TestWeb.AuthHTML do
    |    use TestWeb, :html
    |    embed_templates("auth_html/*")
    |  end
    |end
    |
    """)
    |> assert_has_patch("lib/test_web/controllers/auth_controller.ex", """
    |  use TestWeb, :controller
    |  alias Oidcc.Plug.AuthorizationCallback
    |
    |  plug(
    |    Oidcc.Plug.Authorize,
    |    [
    |      provider: Application.compile_env(:test, [__MODULE__, :provider]),
    |      client_id: &__MODULE__.client_id/0,
    |      client_secret: &__MODULE__.client_secret/0,
    |      redirect_uri: &__MODULE__.callback_uri/0
    |    ]
    |    when action in [:authorize]
    |  )
    |
    |  plug(
    |    AuthorizationCallback,
    |    [
    |      provider: Application.compile_env(:test, [__MODULE__, :provider]),
    |      client_id: &__MODULE__.client_id/0,
    |      client_secret: &__MODULE__.client_secret/0,
    |      redirect_uri: &__MODULE__.callback_uri/0
    |    ]
    |    when action in [:callback]
    |  )
    |
    |  def authorize(conn, _params) do
    |    conn
    |  end
    |
    |  def callback(
    |        %Plug.Conn{private: %{AuthorizationCallback => {:ok, {_token, userinfo}}}} = conn,
    |        params
    |      ) do
    |    conn
    |    |> put_session("oidcc_claims", userinfo)
    |    |> redirect(
    |      to:
    |        case params[:state] do
    |          nil -> "/"
    |          state -> state
    |        end
    |    )
    |  end
    |
    |  def callback(%Plug.Conn{private: %{AuthorizationCallback => {:error, reason}}} = conn, _params) do
    |    conn |> put_status(400) |> render(:error, reason: reason)
    |  end
    |
    |  @doc false
    |  def client_id do
    |    Application.fetch_env!(:test, __MODULE__)[:client_id]
    |  end
    |
    |  @doc false
    |  def client_secret do
    |    Application.fetch_env!(:test, __MODULE__)[:client_secret]
    |  end
    |
    |  @doc false
    |  def callback_uri do
    |    url(~p"/auth/callback")
    |  end
    |end
    |
    """)
    |> assert_has_patch("lib/test_web/controllers/auth_html/error.html.heex", """
    |<p>error:</p>
    |
    |<pre><%= inspect(@reason, pretty: true) %></pre>
    |
    """)
    |> assert_has_patch("lib/test_web/controllers/page_html/home.html.heex", """
    ...|
       |</div>
       |
     + |
     + |<div class="px-4 py-10 sm:px-6 sm:py-28 lg:px-8 xl:px-28 xl:py-32">
     + |  <div class="mx-auto max-w-xl lg:mx-0">
     + |    <div class="group -mx-2 -my-0.5 inline-flex items-center gap-3 px-2 py-0.5">
     + |      <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="h-4 w-4">
     + |        <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 6a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0zM4.501 20.118a7.5 7.5 0 0114.998 0A17.933 17.933 0 0112 21.75c-2.676 0-5.216-.584-7.499-1.632z" />
     + |      </svg>
     + |
     + |      <%= case Plug.Conn.get_session(@conn, "oidcc_claims") do %>
     + |        <% nil -> %>
     + |          <a href={ ~p"/auth/authorize" }>
     + |            Log In
     + |          </a>
     + |        <% %{"sub" => sub} -> %>
     + |          <span class="text-base text-zinc-600">Logged in as <%= sub %></span>
     + |      <% end %>
     + |    </div>
     + |  </div>
     + |</div>
     + |
    """)
    |> assert_has_patch("lib/test_web/router.ex", """
    ...|
       |  end
       |
     + |  scope "/auth", TestWeb do
     + |    pipe_through([:browser])
     + |
     + |    get("/authorize", AuthController, :authorize)
     + |    get("/callback", AuthController, :callback)
     + |    post("/callback", AuthController, :callback)
     + |  end
     + |
       |  scope "/", TestWeb do
       |    pipe_through(:browser)
    ...|
    """)
  end
end
