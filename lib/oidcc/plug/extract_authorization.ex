defmodule Oidcc.Plug.ExtractAuthorization do
  @moduledoc """
  Extract `authorization` request header

  This module should be used together with `Oidcc.Plug.IntrospectToken`,
  `Oidcc.Plug.LoadUserinfo` or `Oidcc.Plug.ValidateJwtToken`.

  ```elixir
  defmodule SampleAppWeb.Endpoint do
    use Phoenix.Endpoint, otp_app: :sample_app

    # ...

    plug Oidcc.Plug.ExtractAuthorization

    plug Oidcc.Plug.IntrospectToken, [...] # Check Token via Introspection
    plug Oidcc.Plug.LoadUserinfo, [...] # Check Token via Userinfo
    plug Oidcc.Plug.ValidateJwtToken, [...] # Check Token via JWT validation

    plug SampleAppWeb.Router
  end
  ```
  """
  @moduledoc since: "0.1.0"

  @behaviour Plug

  import Plug.Conn, only: [get_req_header: 2, put_private: 3, halt: 1, send_resp: 3]

  @typedoc """
  Plug Configuration Options

  ## Options

  * `send_invalid_header_response` - Customize Error Response for invalid header
  """
  @typedoc since: "0.1.0"
  @type opts :: [
          {:send_invalid_header_response,
           (conn :: Plug.Conn.t(), given_header :: [String.t()] -> Plug.Conn.t())}
        ]

  @impl Plug
  def init(opts),
    do: Keyword.validate!(opts, send_invalid_header_response: &send_invalid_header_response/2)

  @impl Plug
  def call(%Plug.Conn{} = conn, opts) do
    send_invalid_header_response = Keyword.fetch!(opts, :send_invalid_header_response)

    case get_req_header(conn, "authorization") do
      ["Bearer " <> token | _rest] -> put_private(conn, __MODULE__, token)
      [] -> put_private(conn, __MODULE__, nil)
      header -> send_invalid_header_response.(conn, header)
    end
  end

  @spec send_invalid_header_response(conn :: Plug.Conn.t(), given_header :: [String.t()]) ::
          Plug.Conn.t()
  defp send_invalid_header_response(conn, [header | _rest]) do
    conn
    |> halt()
    |> send_resp(:bad_request, """
    Invalid authorization Header

    Expected: Authorization: Bearer <token>
    Given: #{inspect(header)}
    """)
  end
end
