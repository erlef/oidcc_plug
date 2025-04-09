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

  * `state` - State to relay to OpenID Provider. Commonly used for target redirect
    URL after authorization.
  """
  @moduledoc since: "0.1.0"

  @behaviour Plug

  import Oidcc.Plug.Config, only: [evaluate_config: 1]

  import Plug.Conn,
    only: [send_resp: 3, put_resp_header: 3, put_session: 3, get_req_header: 2]

  alias Oidcc.Authorization
  alias Oidcc.ClientContext
  alias Oidcc.Plug.Utils

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
  * `client_context_opts` - Options for Client Context Initialization
  * `client_profile_opts` - Options for Client Context Profiles
  * `client_store` - A module name that implements the `Oidcc.Plug.ClientStore` behaviour
    to fetch the client context from a store instead of using the `provider`, `client_id` and `client_secret`
    directly. This is useful for storing the client context in a database or other persistent
    storage.
  """
  @typedoc since: "0.1.0"
  @type opts :: [
          scopes: :oidcc_scope.scopes(),
          redirect_uri: String.t() | (-> String.t()),
          url_extension: :oidcc_http_util.query_params(),
          provider: GenServer.name() | nil,
          client_store: module() | nil,
          client_id: String.t() | (-> String.t()) | nil,
          client_secret: String.t() | (-> String.t()) | nil,
          client_context_opts: :oidcc_client_context.opts() | (-> :oidcc_client_context.opts()) | nil,
          client_profile_opts: :oidcc_profile.opts()
        ]

  @impl Plug
  def init(opts),
    do:
      opts
      |> Keyword.validate!([
        :provider,
        :client_store,
        :client_id,
        :client_secret,
        :redirect_uri,
        :client_context_opts,
        :client_profile_opts,
        url_extension: [],
        scopes: ["openid"]
      ])
      |> Utils.validate_client_context_opts!()

  @impl Plug
  def call(%Plug.Conn{params: params} = conn, opts) do
    redirect_uri = opts |> Keyword.fetch!(:redirect_uri) |> evaluate_config()
    client_profile_opts = Keyword.get(opts, :client_profile_opts, %{profiles: []})

    state = Map.get(params, "state", :undefined)
    state_verifier = :erlang.phash2(state)

    nonce = 31 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
    pkce_verifier = 96 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)

    peer_ip = conn.remote_ip
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

    with {:ok, client_context} <- Utils.get_client_context(conn, opts),
         {:ok, client_context, profile_opts} <-
           apply_profile(client_context, client_profile_opts),
         {:ok, redirect_uri} <-
           Authorization.create_redirect_url(
             client_context,
             Map.merge(profile_opts, authorization_opts)
           ) do
      conn
      |> put_session(get_session_name(), %{
        nonce: nonce,
        peer_ip: peer_ip,
        useragent: useragent,
        pkce_verifier: pkce_verifier,
        state_verifier: state_verifier
      })
      |> put_resp_header("location", IO.iodata_to_binary(redirect_uri))
      |> send_resp(302, "")
    else
      {:error, reason} ->
        raise Error, reason: reason
    end
  end

  defp apply_profile(client_context, profile_opts), do: ClientContext.apply_profiles(client_context, profile_opts)

  @doc false
  @spec get_session_name :: String.t()
  def get_session_name, do: inspect(__MODULE__)
end
