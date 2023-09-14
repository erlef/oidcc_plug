defmodule Oidcc.Plug.ValidateJwtToken do
  @moduledoc """
  Validate extracted authorization token by validating it as a JWT token.

  This module should be used together with `Oidcc.Plug.ExtractAuthorization`.

  ```elixir
  defmodule SampleAppWeb.Endpoint do
    use Phoenix.Endpoint, otp_app: :sample_app

    # ...

    plug Oidcc.Plug.ExtractAuthorization

    plug Oidcc.Plug.ValidateJwtToken,
      provider: SampleApp.GoogleOpenIdConfigurationProvider,
      client_id: Application.compile_env!(:sample_app, [Oidcc.Plug.ValidateJwtToken, :client_id]),
      client_secret: Application.compile_env!(:sample_app, [Oidcc.Plug.ValidateJwtToken, :client_secret])

    plug SampleAppWeb.Router
  end
  ```
  """

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
  * `send_inactive_token_response` - Customize Error Response for inactive token
  """
  @type opts :: [
          provider: GenServer.name(),
          client_id: String.t() | (-> String.t()),
          client_secret: String.t() | (-> String.t()),
          send_inactive_token_response: (conn :: Plug.Conn.t() -> Plug.Conn.t())
        ]

  defmodule Error do
    @moduledoc """
    Validation Failed

    Check the `reason` field for ther exact reason
    """

    defexception [:reason]

    @impl Exception
    def message(_exception), do: "Validation Failed"
  end

  @impl Plug
  def init(opts),
    do:
      Keyword.validate!(opts, [
        :provider,
        :client_id,
        :client_secret,
        send_inactive_token_response: &send_inactive_token_response/1
      ])

  @impl Plug
  def call(%Plug.Conn{private: %{ExtractAuthorization => nil}} = conn, _opts), do: conn

  def call(%Plug.Conn{private: %{ExtractAuthorization => access_token}} = conn, opts) do
    provider = Keyword.fetch!(opts, :provider)
    client_id = opts |> Keyword.fetch!(:client_id) |> evaluate_config()
    client_secret = opts |> Keyword.fetch!(:client_secret) |> evaluate_config()

    send_inactive_token_response = Keyword.fetch!(opts, :send_inactive_token_response)

    with {:ok, client_context} <-
           Oidcc.ClientContext.from_configuration_worker(provider, client_id, client_secret),
         {:ok, claims} <- Oidcc.Token.validate_id_token(access_token, client_context, :any) do
      put_private(conn, __MODULE__, claims)
    else
      {:error, :token_expired} ->
        conn
        |> put_private(__MODULE__, nil)
        |> send_inactive_token_response.()

      {:error, reason} ->
        raise Error, reason: reason
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
