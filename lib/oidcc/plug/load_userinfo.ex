defmodule Oidcc.Plug.LoadUserinfo do
  @moduledoc """
  Validate extracted authorization token using introspection.

  See: https://openid.net/specs/openid-connect-core-1_0.html#UserInfo

  This module should be used together with `Oidcc.Plug.ExtractAuthorization`.

  This plug will send a userinfo request for ever request. To avoid this,
  provide a `cache` to `t:opts/0`.

  ```elixir
  defmodule SampleAppWeb.Endpoint do
    use Phoenix.Endpoint, otp_app: :sample_app

    # ...

    plug Oidcc.Plug.ExtractAuthorization

    plug Oidcc.Plug.LoadUserinfo,
      provider: SampleApp.GoogleOpenIdConfigurationProvider,
      client_id: Application.compile_env!(:sample_app, [Oidcc.Plug.LoadUserinfo, :client_id]),
      client_secret: Application.compile_env!(:sample_app, [Oidcc.Plug.LoadUserinfo, :client_secret])

    plug SampleAppWeb.Router
  end
  ```
  """

  @behaviour Plug

  import Plug.Conn, only: [put_private: 3, halt: 1, send_resp: 3]

  alias Oidcc.Plug.ExtractAuthorization

  @typedoc """
  Plug Configuration Options

  ## Options

  * `provider` - name of the `Oidcc.ProviderConfiguration.Worker`
  * `client_id` - OAuth Client ID to use for the introspection
  * `client_secret` - OAuth Client Secret to use for the introspection
  * `userinfo_retrieve_opts` - Options to pass to userinfo loading
  * `send_inactive_token_response` - Customize Error Response for inactive token
  * `cache` - Cache userinfo response - See `Oidcc.Plug.Cache`
  """
  @type opts :: [
          provider: GenServer.name(),
          client_id: String.t(),
          client_secret: String.t(),
          userinfo_retrieve_opts: :oidcc_userinfo.retrieve_opts(),
          send_inactive_token_response: (conn :: Plug.Conn.t() -> Plug.Conn.t()),
          cache: Oidcc.Plug.Cache.t()
        ]

  defmodule Error do
    @moduledoc """
    Retrieve Userinfo Failed

    Check the `reason` field for ther exact reason
    """

    defexception [:reason]

    @impl Exception
    def message(_exception), do: "Retrieve Userinfo Load Failed"
  end

  @impl Plug
  def init(opts),
    do:
      Keyword.validate!(opts, [
        :provider,
        :client_id,
        :client_secret,
        userinfo_retrieve_opts: %{},
        send_inactive_token_response: &send_inactive_token_response/1,
        cache: Oidcc.Plug.Cache.Noop
      ])

  @impl Plug
  def call(%Plug.Conn{private: %{ExtractAuthorization => nil}} = conn, _opts), do: conn

  def call(%Plug.Conn{private: %{ExtractAuthorization => access_token}} = conn, opts) do
    provider = Keyword.fetch!(opts, :provider)
    client_id = Keyword.fetch!(opts, :client_id)
    client_secret = Keyword.fetch!(opts, :client_secret)

    userinfo_retrieve_opts =
      opts
      |> Keyword.fetch!(:userinfo_retrieve_opts)
      |> Map.put_new(:expected_subject, :any)

    send_inactive_token_response = Keyword.fetch!(opts, :send_inactive_token_response)

    cache = Keyword.fetch!(opts, :cache)

    case cache.get(:userinfo, access_token, conn) do
      {:ok, %{} = claims} ->
        put_private(conn, __MODULE__, claims)

      :miss ->
        case Oidcc.retrieve_userinfo(
               access_token,
               provider,
               client_id,
               client_secret,
               userinfo_retrieve_opts
             ) do
          {:ok, claims} ->
            :ok = cache.put(:introspection, access_token, claims, conn)

            put_private(conn, __MODULE__, claims)

          {:error, {:http_error, 401, _body}} ->
            conn
            |> put_private(__MODULE__, nil)
            |> send_inactive_token_response.()

          {:error, reason} ->
            raise Error, reason: reason
        end
    end
  end

  def call(%Plug.Conn{} = _conn, _opts) do
    raise """
    The plug Oidcc.Plug.ExtractAuthorization must be run before this plug
    """
  end

  @spec send_inactive_token_response(conn :: Plug.Conn.t()) :: Plug.Conn.t()
  defp send_inactive_token_response(conn) do
    conn
    |> halt()
    |> send_resp(:unauthorized, "The provided token is inactive")
  end
end
