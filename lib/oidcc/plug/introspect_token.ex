defmodule Oidcc.Plug.IntrospectToken do
  @moduledoc """
  Validate extracted authorization token using introspection.

  See: https://datatracker.ietf.org/doc/html/rfc7662

  This module should be used together with `Oidcc.Plug.ExtractAuthorization`.

  This plug will send an introspection request for ever request. To avoid this,
  provide a `cache` to the options.

  ```elixir
  defmodule SampleAppWeb.Endpoint do
    use Phoenix.Endpoint, otp_app: :sample_app

    # ...

    plug Oidcc.Plug.ExtractAuthorization

    plug Oidcc.Plug.IntrospectToken,
      provider: SampleApp.GoogleOpenIdConfigurationProvider,
      client_id: Application.compile_env!(:sample_app, [Oidcc.Plug.IntrospectToken, :client_id]),
      client_secret: Application.compile_env!(:sample_app, [Oidcc.Plug.IntrospectToken, :client_secret])

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
  * `token_introspection_opts` - Options to pass to the introspection
  * `send_inactive_token_response` - Customize Error Response for inactive token
  * `cache` - Cache token introspection
  """
  @type opts :: [
          provider: GenServer.name(),
          client_id: String.t(),
          client_secret: String.t(),
          token_introspection_opts: :oidcc_token_introspection.opts(),
          send_inactive_token_response:
            (conn :: Plug.Conn.t(), introspection :: Oidcc.TokenIntrospection.t() ->
               Plug.Conn.t()),
          cache:
            (conn :: Plug.Conn.t(), token :: String.t() ->
               {:ok, Oidcc.TokenIntrospection.t()} | :not_found)
        ]

  defmodule Error do
    @moduledoc """
    Introspection Failed

    Check the `reason` field for ther exact reason
    """

    defexception [:reason]

    @impl Exception
    def message(_exception), do: "Introspection Failed"
  end

  @impl Plug
  def init(opts),
    do:
      Keyword.validate!(opts, [
        :provider,
        :client_id,
        :client_secret,
        token_introspection_opts: %{},
        send_inactive_token_response: &send_inactive_token_response/2,
        cache: &noop_cache/2
      ])

  @impl Plug
  def call(%Plug.Conn{private: %{ExtractAuthorization => nil}} = conn, _opts), do: conn

  def call(%Plug.Conn{private: %{ExtractAuthorization => access_token}} = conn, opts) do
    provider = Keyword.fetch!(opts, :provider)
    client_id = Keyword.fetch!(opts, :client_id)
    client_secret = Keyword.fetch!(opts, :client_secret)

    token_introspection_opts = Keyword.fetch!(opts, :token_introspection_opts)

    send_inactive_token_response = Keyword.fetch!(opts, :send_inactive_token_response)

    cache = Keyword.fetch!(opts, :cache)

    case cache.(conn, access_token) do
      {:ok, introspection} ->
        put_private(conn, __MODULE__, introspection)

      :not_found ->
        case Oidcc.introspect_token(
               access_token,
               provider,
               client_id,
               client_secret,
               token_introspection_opts
             ) do
          {:ok, %Oidcc.TokenIntrospection{active: true} = introspection} ->
            put_private(conn, __MODULE__, introspection)

          {:ok, %Oidcc.TokenIntrospection{active: false} = introspection} ->
            conn
            |> put_private(__MODULE__, introspection)
            |> send_inactive_token_response.(introspection)

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

  @spec send_inactive_token_response(
          conn :: Plug.Conn.t(),
          introspection :: Oidcc.TokenIntrospection.t()
        ) :: Plug.Conn.t()
  defp send_inactive_token_response(conn, _introspection) do
    conn
    |> halt()
    |> send_resp(:unauthorized, "The provided token is inactive")
  end

  @spec noop_cache(conn :: Plug.Conn.t(), token :: String.t()) ::
          {:ok, Oidcc.TokenIntrospection.t()} | :not_found
  defp noop_cache(_conn, _token), do: :not_found
end
