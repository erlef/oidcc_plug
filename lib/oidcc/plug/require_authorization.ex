defmodule Oidcc.Plug.RequireAuthorization do
  @moduledoc """
  Ensure authorization token provided.

  This module should be used together with `Oidcc.Plug.ExtractAuthorization`.

  ```elixir
  defmodule SampleAppWeb.Endpoint do
    use Phoenix.Endpoint, otp_app: :sample_app

    # ...

    plug Oidcc.Plug.ExtractAuthorization

    plug Oidcc.Plug.RequireAuthorization

    # Check Token with `Oidcc.Plug.IntrospectToken`, `Oidcc.Plug.LoadUserinfo` or `Oidcc.Plug.ValidateJwtToken`

    plug SampleAppWeb.Router
  end
  ```
  """
  @moduledoc since: "0.1.0"

  @behaviour Plug

  import Plug.Conn, only: [halt: 1, send_resp: 3, put_resp_header: 3]

  alias Oidcc.Plug.ExtractAuthorization

  @typedoc """
  Plug Configuration Options

  ## Options

  * `send_missing_token_response` - Customize Error Response for missing token
  """
  @typedoc since: "0.1.0"
  @type opts :: [
          send_missing_token_response: (conn :: Plug.Conn.t() -> Plug.Conn.t())
        ]

  @impl Plug
  def init(opts), do: Keyword.validate!(opts, send_missing_token_response: &__MODULE__.send_missing_token_response/1)

  @impl Plug
  def call(%Plug.Conn{private: %{ExtractAuthorization => nil}} = conn, opts) do
    send_missing_token_response = Keyword.fetch!(opts, :send_missing_token_response)

    send_missing_token_response.(conn)
  end

  def call(%Plug.Conn{private: %{ExtractAuthorization => _access_token}} = conn, _opts), do: conn

  def call(%Plug.Conn{} = _conn, _opts) do
    raise """
    The plug Oidcc.Plug.ExtractAuthorization must be run before this plug
    """
  end

  @doc false
  @spec send_missing_token_response(conn :: Plug.Conn.t()) :: Plug.Conn.t()
  def send_missing_token_response(conn) do
    conn
    |> halt()
    |> put_resp_header("www-authenticate", "Bearer")
    |> send_resp(:unauthorized, "The authorization token is required")
  end
end
