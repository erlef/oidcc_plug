defmodule Oidcc.Plug.AuthorizationCallback do
  @moduledoc """
  Retrieve Token for Code Flow Authorization Callback

  This plug does not send a response. Instead it will load and validate all
  token data and leave the rest to a controller action that will be executed
  after.

  ## Via `Phoenix.Router`

  ```elixir
  defmodule SampleAppWeb.Router do
    use Phoenix.Router

    # ...

    pipeline :oidcc_callback do
      plug Oidcc.Plug.AuthorizationCallback,
        provider: SampleApp.GoogleOpenIdConfigurationProvider,
        client_id: Application.compile_env!(:sample_app, [Oidcc.Plug.Authorize, :client_id]),
        client_secret: Application.compile_env!(:sample_app, [Oidcc.Plug.Authorize, :client_secret]),
        redirect_uri: "https://localhost:4000/oidcc/callback"
    end

    forward "/oidcc/authorize", to: Oidcc.Plug.Authorize,
      init_opts: [...]

    scope "/oidcc/callback", SampleAppWeb do
      pipe_through :oidcc_callback

      get "/", AuthController, :handle_callback
      post "/", AuthController, :handle_callback
    end
  end
  ```

  ## Via `Controller`

  ```elixir
  defmodule SampleAppWeb.AuthController do
    # ...

    plug Oidcc.Plug.AuthorizationCallback,
      provider: SampleApp.GoogleOpenIdConfigurationProvider,
      client_id: Application.compile_env!(:sample_app, [Oidcc.Plug.Authorize, :client_id]),
      client_secret: Application.compile_env!(:sample_app, [Oidcc.Plug.Authorize, :client_secret]),
      redirect_uri: "https://localhost:4000/oidcc/callback"
      when action in [:handle_callback]

    def handle_callback(
      %Plug.Conn{private: %{
        Oidcc.Plug.AuthorizationCallback => {:ok, {token, userinfo}}
      }},
      _params
    ) do
      # Handle Success

      conn
      |> put_session("auth_token", token)
      |> put_session("auth_userinfo", userinfo)
      |> redirect(to: "/")
    end

    def handle_callback(
      %Plug.Conn{private: %{
        Oidcc.Plug.AuthorizationCallback => {:error, reason}}
      },
      _params
    ) do
      # Handle Error

      conn
      |> put_status(400)
      |> render("error.html", reason: reason)
    end
  end
  ```
  """
  @moduledoc since: "0.1.0"

  @behaviour Plug

  alias Oidcc.ClientContext
  alias Oidcc.Plug.Authorize
  alias Oidcc.ProviderConfiguration
  alias Oidcc.Token
  alias Oidcc.Userinfo

  import Plug.Conn,
    only: [get_session: 2, delete_session: 2, put_private: 3, get_req_header: 2]

  import Oidcc.Plug.Config, only: [evaluate_config: 1]

  @typedoc """
  Plug Configuration Options

  ## Options

  * `provider` - name of the `Oidcc.ProviderConfiguration.Worker`
  * `client_id` - OAuth Client ID to use for the introspection
  * `client_secret` - OAuth Client Secret to use for the introspection
  * `client_context_opts` - Options for Client Context Initialization
  * `client_profile_opts` - Options for Client Context Profiles
  * `redirect_uri` - Where to redirect for callback
  * `check_useragent` - check if useragent is the same as before the
    authorization request
  * `check_peer_ip` - check if the client IP is the same as before the
    authorization request
  * `retrieve_userinfo` - whether to load userinfo from the provider
  * `request_opts` - request opts for http calls to provider
  * `client_store` - A module name that implements the `Oidcc.Plug.ClientStore` behaviour
  to fetch the client context from a store instead of using the `provider`, `client_id` and `client_secret`
  directly. This is useful for storing the client context in a database or other persistent
  storage.
  """
  @typedoc since: "0.1.0"
  @type opts() :: [
          provider: GenServer.name() | nil,
          client_store: module() | nil,
          client_id: String.t() | (-> String.t()) | nil,
          client_secret: String.t() | (-> String.t()) | nil,
          client_context_opts: :oidcc_client_context.opts() | (-> :oidcc_client_context.opts()),
          client_profile_opts: :oidcc_profile.opts(),
          redirect_uri: String.t() | (-> String.t()),
          check_useragent: boolean(),
          check_peer_ip: boolean(),
          retrieve_userinfo: boolean(),
          request_opts: :oidcc_http_util.request_opts()
        ]

  @typedoc since: "0.1.0"
  @type error() ::
          :oidcc_client_context.error()
          | :oidcc_token.error()
          | :oidcc_userinfo.error()
          | :useragent_mismatch
          | :peer_ip_mismatch
          | {:missing_request_param, param :: String.t()}

  @impl Plug
  def init(opts),
    do:
      Keyword.validate!(opts, [
        :provider,
        :client_id,
        :client_store,
        :client_secret,
        :client_context_opts,
        :client_profile_opts,
        :redirect_uri,
        :preferred_auth_methods,
        check_useragent: true,
        check_peer_ip: true,
        retrieve_userinfo: true,
        request_opts: %{}
      ])

  @impl Plug
  def call(%Plug.Conn{params: params, body_params: body_params} = conn, opts) do
    redirect_uri = opts |> Keyword.fetch!(:redirect_uri) |> evaluate_config()
    client_profile_opts = opts |> Keyword.get(:client_profile_opts, %{profiles: []})

    params = Map.merge(params, body_params)

    %{
      nonce: nonce,
      peer_ip: peer_ip,
      useragent: useragent,
      pkce_verifier: pkce_verifier,
      state_verifier: state_verifier
    } =
      case get_session(conn, Authorize.get_session_name()) do
        nil ->
          %{
            nonce: :any,
            peer_ip: nil,
            useragent: nil,
            pkce_verifier: :none,
            state_verifier: :none
          }

        %{} = session ->
          session
      end

    check_peer_ip? = Keyword.fetch!(opts, :check_peer_ip)
    check_useragent? = Keyword.fetch!(opts, :check_useragent)
    retrieve_userinfo? = Keyword.fetch!(opts, :retrieve_userinfo)

    result =
      with {:ok, client_context} <-
             get_client_context(conn, opts),
           {:ok, client_context, profile_opts} <-
             apply_profile(client_context, client_profile_opts),
           :ok <- check_peer_ip(conn, peer_ip, check_peer_ip?),
           :ok <- check_useragent(conn, useragent, check_useragent?),
           :ok <- check_state(params, state_verifier),
           :ok <- check_issuer_request_param(params, client_context),
           {:ok, code} <- fetch_request_param(params, "code"),
           scope = Map.get(params, "scope", "openid"),
           token_opts =
             prepare_retrieve_opts(opts, scope, nonce, redirect_uri, pkce_verifier),
           {:ok, token} <-
             retrieve_token(
               code,
               client_context,
               retrieve_userinfo?,
               Map.merge(profile_opts, token_opts)
             ),
           {:ok, userinfo} <-
             retrieve_userinfo(token, client_context, retrieve_userinfo?) do
        {:ok, {token, userinfo}}
      end

    conn
    |> delete_session(Authorize.get_session_name())
    |> put_private(__MODULE__, result)
  end

  defp get_client_context(conn, opts) do
    if client_store = Keyword.get(opts, :client_store) do
      client_store.get_client_context(conn)
    else
      provider = Keyword.fetch!(opts, :provider)

      client_id = opts |> Keyword.fetch!(:client_id) |> evaluate_config()
      client_secret = opts |> Keyword.fetch!(:client_secret) |> evaluate_config()

      client_context_opts = opts |> Keyword.get(:client_context_opts, %{}) |> evaluate_config()

      ClientContext.from_configuration_worker(
        provider,
        client_id,
        client_secret,
        client_context_opts
      )
    end
  end

  @spec prepare_retrieve_opts(
          opts :: opts(),
          scope :: String.t(),
          nonce :: String.t() | :any,
          redirect_uri :: String.t(),
          pkce_verifier :: String.t() | :none
        ) :: :oidcc_token.retrieve_opts()
  defp prepare_retrieve_opts(opts, scope, nonce, redirect_uri, pkce_verifier) do
    scopes = :oidcc_scope.parse(scope)

    refresh_jwks =
      if client_store = Keyword.get(opts, :client_store) do
        if function_exported?(client_store, :refresh_jwks, 1),
          do: &client_store.refresh_jwks/1,
          else: nil
      else
        provider = Keyword.fetch!(opts, :provider)
        :oidcc_jwt_util.refresh_jwks_fun(provider)
      end

    opts
    |> Keyword.take([:request_opts, :preferred_auth_methods])
    |> Map.new()
    |> Map.merge(%{
      nonce: nonce,
      scope: scopes,
      redirect_uri: redirect_uri,
      pkce_verifier: pkce_verifier,
      refresh_jwks: refresh_jwks
    })
    |> case do
      %{pkce_verifier: :none} = opts -> Map.drop(opts, [:pkce_verifier])
      opts -> opts
    end
  end

  @spec check_peer_ip(
          conn :: Plug.Conn.t(),
          peer_ip :: :inet.ip_address() | nil,
          check_peer_ip? :: boolean()
        ) :: :ok | {:error, error()}
  defp check_peer_ip(conn, peer_ip, check_peer_ip?)
  defp check_peer_ip(_conn, _peer_ip, false), do: :ok
  defp check_peer_ip(_conn, nil, true), do: :ok
  defp check_peer_ip(%Plug.Conn{remote_ip: peer_ip}, peer_ip, true), do: :ok
  defp check_peer_ip(%Plug.Conn{}, _peer_ip, true), do: {:error, :peer_ip_mismatch}

  @spec check_useragent(
          conn :: Plug.Conn.t(),
          useragent :: String.t() | nil,
          check_useragent? :: boolean()
        ) :: :ok | {:error, error()}
  defp check_useragent(conn, useragent, check_useragent?)
  defp check_useragent(_conn, _useragent, false), do: :ok
  defp check_useragent(_conn, nil, true), do: :ok

  defp check_useragent(%Plug.Conn{} = conn, useragent, true) do
    case get_req_header(conn, "user-agent") do
      [^useragent | _rest] -> :ok
      _header -> {:error, :useragent_mismatch}
    end
  end

  @spec fetch_request_param(params :: %{String.t() => term()}, param :: String.t()) ::
          {:ok, term()} | {:error, error()}
  defp fetch_request_param(params, param) do
    case Map.fetch(params, param) do
      {:ok, value} -> {:ok, value}
      :error -> {:error, {:missing_request_param, param}}
    end
  end

  defp check_issuer_request_param(params, client_context)

  defp check_issuer_request_param(params, %ClientContext{
         provider_configuration: %ProviderConfiguration{
           issuer: issuer,
           authorization_response_iss_parameter_supported: true
         }
       }) do
    with {:ok, given_issuer} <- fetch_request_param(params, "iss") do
      if issuer == given_issuer do
        :ok
      else
        {:error, {:invalid_issuer, given_issuer}}
      end
    end
  end

  defp check_issuer_request_param(_params, _client_context), do: :ok

  defp check_state(params, state_verifier)
  defp check_state(%{"state" => _state}, :none), do: {:error, :state_not_verified}
  defp check_state(_params, :none), do: :ok

  defp check_state(%{"state" => state}, state_verifier) do
    if :erlang.phash2(state) == state_verifier do
      :ok
    else
      {:error, :state_not_verified}
    end
  end

  defp check_state(_params, _state), do: :ok

  @spec retrieve_token(
          code :: String.t(),
          client_context :: ClientContext.t(),
          retrieve_userinfo? :: boolean(),
          token_opts :: :oidcc_token.retrieve_opts()
        ) :: {:ok, Oidcc.Token.t()} | {:error, error()}
  defp retrieve_token(code, client_context, retrieve_userinfo?, token_opts) do
    case Token.retrieve(code, client_context, token_opts) do
      {:ok, token} -> {:ok, token}
      {:error, {:none_alg_used, token}} when retrieve_userinfo? -> {:ok, token}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec retrieve_userinfo(
          token :: Oidcc.Token.t(),
          client_context :: ClientContext.t(),
          retrieve_userinfo? :: true
        ) :: {:ok, :oidcc_jwt_util.claims()} | {:error, error()}
  @spec retrieve_userinfo(
          token :: Oidcc.Token.t(),
          client_context :: ClientContext.t(),
          retrieve_userinfo? :: false
        ) :: {:ok, nil} | {:error, error()}
  defp retrieve_userinfo(token, client_context, retrieve_userinfo?)
  defp retrieve_userinfo(_token, _client_context, false), do: {:ok, nil}

  defp retrieve_userinfo(token, client_context, true),
    do: Userinfo.retrieve(token, client_context, %{})

  defp apply_profile(client_context, profile_opts),
    do: ClientContext.apply_profiles(client_context, profile_opts)
end
