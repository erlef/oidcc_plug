defmodule Oidcc.Plug.IntrospectToken do
  @moduledoc """
  Validate extracted authorization token using introspection.

  See: https://datatracker.ietf.org/doc/html/rfc7662

  This module should be used together with `Oidcc.Plug.ExtractAuthorization`.

  This plug will send an introspection request for every request. To avoid this,
  provide a `cache` to `t:opts/0`.

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
  @moduledoc since: "0.1.0"

  @behaviour Plug

  import Plug.Conn, only: [put_private: 3, halt: 1, send_resp: 3]

  import Oidcc.Plug.Config, only: [evaluate_config: 1]

  alias Oidcc.Plug.ExtractAuthorization

  @typedoc """
  Plug Configuration Options

  ## Options

  * `provider` - name of the `Oidcc.ProviderConfiguration.Worker`
  * `client_id` - OAuth Client ID to use for the introspection
  * `client_secret` - OAuth Client Secret to use for the introspection
  * `token_introspection_opts` - Options to pass to the introspection
  * `send_inactive_token_response` - Customize Error Response for inactive token
  * `cache` - Cache token introspection - See `Oidcc.Plug.Cache`
  """
  @typedoc since: "0.1.0"
  @type opts :: [
          provider: GenServer.name(),
          client_id: String.t() | (-> String.t()),
          client_secret: String.t() | (-> String.t()),
          token_introspection_opts: :oidcc_token_introspection.opts(),
          send_inactive_token_response: (conn :: Plug.Conn.t(),
                                         introspection :: Oidcc.TokenIntrospection.t() ->
                                           Plug.Conn.t()),
          cache: Oidcc.Plug.Cache.t()
        ]

  defmodule Error do
    @moduledoc """
    Introspection Failed

    Check the `reason` field for ther exact reason
    """
    @moduledoc since: "0.1.0"

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
        send_inactive_token_response: &__MODULE__.send_inactive_token_response/2,
        cache: Oidcc.Plug.Cache.Noop
      ])

  @impl Plug
  def call(%Plug.Conn{private: %{ExtractAuthorization => nil}} = conn, _opts), do: conn

  def call(%Plug.Conn{private: %{ExtractAuthorization => access_token}} = conn, opts) do
    provider = Keyword.fetch!(opts, :provider)
    client_id = opts |> Keyword.fetch!(:client_id) |> evaluate_config()
    client_secret = opts |> Keyword.fetch!(:client_secret) |> evaluate_config()

    token_introspection_opts = Keyword.fetch!(opts, :token_introspection_opts)

    send_inactive_token_response = Keyword.fetch!(opts, :send_inactive_token_response)

    cache = Keyword.fetch!(opts, :cache)

    case cache.get(:introspection, access_token, conn) do
      {:ok, %Oidcc.TokenIntrospection{active: true} = introspection} ->
        put_private(conn, __MODULE__, introspection)

      {:ok, %Oidcc.TokenIntrospection{active: false} = introspection} ->
        conn
        |> put_private(__MODULE__, introspection)
        |> send_inactive_token_response.(introspection)

      :miss ->
        case Oidcc.introspect_token(
               access_token,
               provider,
               client_id,
               client_secret,
               token_introspection_opts
             ) do
          {:ok, %Oidcc.TokenIntrospection{active: true} = introspection} ->
            :ok = cache.put(:introspection, access_token, introspection, conn)

            put_private(conn, __MODULE__, introspection)

          {:ok, %Oidcc.TokenIntrospection{active: false} = introspection} ->
            :ok = cache.put(:introspection, access_token, introspection, conn)

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

  @doc false
  @spec send_inactive_token_response(
          conn :: Plug.Conn.t(),
          introspection :: Oidcc.TokenIntrospection.t()
        ) :: Plug.Conn.t()
  def send_inactive_token_response(conn, _introspection) do
    conn
    |> halt()
    |> send_resp(:unauthorized, "The provided token is inactive")
  end
end
