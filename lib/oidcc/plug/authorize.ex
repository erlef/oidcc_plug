defmodule Oidcc.Plug.Authorize do
  @moduledoc """
  Initiate Code Flow Authorization Redirect

  ```elixir
  defmodule SampleAppWeb.Router do
    use Phoenix.Router

    # ...

    forward "/oidcc/authorize", to: Oidcc.Plug.Authorize,
      init_opts: [
        provider: SampleApp.GoogleOpenIdConfigurationProvider,
        client_id: Application.compile_env!(:sample_app, [Oidcc.Plug.Authorize, :client_id]),
        client_secret: Application.compile_env!(:sample_app, [Oidcc.Plug.Authorize, :client_secret]),
        redirect_uri: "https://localhost:4000/oidcc/callback"
      ]
  end
  ```

  ## Query Params

  * `state` - STate to relay to OpenID Provider. Commonly used for target redirect
    URL after authorization.
  """
  @moduledoc since: "0.1.0"

  @behaviour Plug

  import Plug.Conn,
    only: [send_resp: 3, put_resp_header: 3, put_session: 3, get_peer_data: 1, get_req_header: 2]

  import Oidcc.Plug.Config, only: [evaluate_config: 1]

  defmodule Error do
    @moduledoc """
    Redirect URI Generation Failed

    Check the `reason` field for ther exact reason
    """
    @moduledoc since: "0.1.0"

    defexception [:reason]

    @impl Exception
    def message(_exception), do: "Redirect URI Generation Failed"
  end

  @typedoc """
  Plug Configuration Options

  ## Options

  * `scopes` - scopes to request
  * `redirect_uri` - Where to redirect for callback
  * `url_extension` - Custom query parameters to add to the redirect URI
  * `provider` - name of the `Oidcc.ProviderConfiguration.Worker`
  * `client_id` - OAuth Client ID to use for the introspection
  * `client_secret` - OAuth Client Secret to use for the introspection
  """
  @typedoc since: "0.1.0"
  @type opts :: [
          scopes: :oidcc_scope.scopes(),
          redirect_uri: String.t() | (-> String.t()),
          url_extension: :oidcc_http_util.query_params(),
          provider: GenServer.name(),
          client_id: String.t() | (-> String.t()),
          client_secret: String.t() | (-> String.t())
        ]

  @impl Plug
  def init(opts),
    do:
      Keyword.validate!(opts, [
        :provider,
        :client_id,
        :client_secret,
        :redirect_uri,
        url_extension: [],
        scopes: ["openid"]
      ])

  @impl Plug
  def call(%Plug.Conn{params: params} = conn, opts) do
    provider = Keyword.fetch!(opts, :provider)
    client_id = opts |> Keyword.fetch!(:client_id) |> evaluate_config()
    client_secret = opts |> Keyword.fetch!(:client_secret) |> evaluate_config()
    redirect_uri = opts |> Keyword.fetch!(:redirect_uri) |> evaluate_config()

    state = Map.get(params, "state", :undefined)
    nonce = 96 |> :crypto.strong_rand_bytes() |> Base.encode64(padding: false)
    pkce_verifier = 96 |> :crypto.strong_rand_bytes() |> Base.encode64(padding: false)

    %{address: peer_ip} = get_peer_data(conn)

    useragent = conn |> get_req_header("User-Agent") |> List.first()

    authorization_opts =
      opts
      |> Keyword.take([:url_extension, :scopes])
      |> Keyword.merge(
        nonce: nonce,
        state: state,
        redirect_uri: redirect_uri,
        pkce_verifier: pkce_verifier
      )
      |> Map.new()

    case Oidcc.create_redirect_url(provider, client_id, client_secret, authorization_opts) do
      {:ok, redirect_uri} ->
        conn
        |> put_session(get_session_name(), %{
          nonce: nonce,
          peer_ip: peer_ip,
          useragent: useragent,
          pkce_verifier: pkce_verifier
        })
        |> put_resp_header("location", IO.iodata_to_binary(redirect_uri))
        |> send_resp(302, "")

      {:error, reason} ->
        raise Error, reason: reason
    end
  end

  @doc false
  @spec get_session_name :: String.t()
  def get_session_name, do: inspect(__MODULE__)
end
