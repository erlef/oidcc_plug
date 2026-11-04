# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-FileCopyrightText: 2025 Benedikt Reinartz
# SPDX-FileCopyrightText: 2025 Matt Enlow
# SPDX-FileCopyrightText: 2025 Yannis Weishaupt
# SPDX-FileCopyrightText: 2026 Mathias Polligkeit
#
# SPDX-License-Identifier: Apache-2.0

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
      client_secret: Application.compile_env!(:sample_app, [Oidcc.Plug.ValidateJwtToken, :client_secret]),
      # optional validation options to pass to Oidcc.Token.validate_id_token/3
      validate_opts: %{validate_azp: :any}

    plug SampleAppWeb.Router
  end
  ```
  """
  @moduledoc since: "0.1.0"

  @behaviour Plug

  import Plug.Conn, only: [put_private: 3, halt: 1, send_resp: 3]

  alias Oidcc.Plug.ExtractAuthorization
  alias Oidcc.Plug.Utils

  @typedoc """
  Plug Configuration Options

  ## Options

  * `provider` - name of the `Oidcc.ProviderConfiguration.Worker`
  * `client_id` - OAuth Client ID to use for the token validation
  * `client_secret` - OAuth Client Secret to use for the token validation
  * `send_inactive_token_response` - Customize Error Response for inactive token
  * `client_store` - A module name that implements the `Oidcc.Plug.ClientStore` behaviour
  to fetch the client context from a store instead of using the `provider`, `client_id` and `client_secret`
  directly. This is useful for storing the client context in a database or other persistent
  storage.
  * `validate_opts` - A map of options to pass to `Oidcc.Token.validate_id_token/3`.
  """
  @typedoc since: "0.1.0"
  @type opts :: [
          provider: GenServer.name() | nil,
          client_store: module() | nil,
          client_id: String.t() | (-> String.t()) | nil,
          client_secret: String.t() | (-> String.t()) | nil,
          send_inactive_token_response: (conn :: Plug.Conn.t() -> Plug.Conn.t()),
          validate_opts: Oidcc.Token.retrieve_opts()
        ]

  defmodule Error do
    @moduledoc """
    Validation Failed

    Check the `reason` field for ther exact reason
    """
    @moduledoc since: "0.1.0"

    defexception [:reason]

    @impl Exception
    def message(_exception), do: "Validation Failed"
  end

  @impl Plug
  def init(opts),
    do:
      opts
      |> Keyword.validate!([
        :provider,
        :client_store,
        :client_id,
        :client_secret,
        send_inactive_token_response: &__MODULE__.send_inactive_token_response/1,
        validate_opts: %{}
      ])
      |> Utils.validate_client_context_opts!()

  @impl Plug
  def call(%Plug.Conn{private: %{ExtractAuthorization => nil}} = conn, _opts), do: conn

  def call(%Plug.Conn{private: %{ExtractAuthorization => access_token}} = conn, opts) do
    send_inactive_token_response = Keyword.fetch!(opts, :send_inactive_token_response)

    with {:ok, client_context} <-
           Utils.get_client_context(conn, opts),
         validate_opts = prepare_validate_opts(client_context, opts),
         {:ok, claims} <-
           Oidcc.Token.validate_id_token(access_token, client_context, validate_opts) do
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

  @spec prepare_validate_opts(client_context :: Oidcc.ClientContext.t(), opts :: opts()) ::
          Oidcc.Token.retrieve_opts()
  defp prepare_validate_opts(client_context, opts) do
    opts
    |> Keyword.fetch!(:validate_opts)
    |> Map.put(:nonce, :any)
    |> Utils.put_refresh_jwks(client_context, opts)
  end

  @doc false
  @spec send_inactive_token_response(conn :: Plug.Conn.t()) :: Plug.Conn.t()
  def send_inactive_token_response(conn) do
    conn
    |> halt()
    |> send_resp(:unauthorized, "The provided token is inactive")
  end
end
