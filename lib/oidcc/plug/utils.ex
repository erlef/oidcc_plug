defmodule Oidcc.Plug.Utils do
  @moduledoc false

  import Oidcc.Plug.Config, only: [evaluate_config: 2]

  alias Oidcc.ClientContext

  @doc """
  Returns a client context from either a client store or a configuration worker.
  """
  @spec get_client_context(Plug.Conn.t(), Keyword.t()) ::
          {:ok, ClientContext.t()} | {:error, term()}
  def get_client_context(conn, opts) do
    if client_store = Keyword.get(opts, :client_store) do
      client_store.get_client_context(conn)
    else
      provider = Keyword.get(opts, :provider)
      client_id = opts |> Keyword.get(:client_id) |> evaluate_config(conn)
      client_secret = opts |> Keyword.get(:client_secret) |> evaluate_config(conn)
      client_context_opts = opts |> Keyword.get(:client_context_opts, %{}) |> evaluate_config(conn)

      ClientContext.from_configuration_worker(
        provider,
        client_id,
        client_secret,
        client_context_opts
      )
    end
  end

  @doc """
  Returns a function to refresh the JWKS for a provider.
  """
  @spec get_refresh_jwks_fun(Keyword.t()) ::
          :oidcc_jwt_util.refresh_jwks_for_unknown_kid_fun() | nil
  def get_refresh_jwks_fun(opts) do
    if client_store = Keyword.get(opts, :client_store) do
      if function_exported?(client_store, :refresh_jwks, 1),
        do: &client_store.refresh_jwks/1
    else
      provider = Keyword.fetch!(opts, :provider)
      :oidcc_jwt_util.refresh_jwks_fun(provider)
    end
  end

  @doc """
  Validates the client context options.

  Raises an ArgumentError if the options are invalid.
  """
  @spec validate_client_context_opts!(Keyword.t()) :: Keyword.t()
  def validate_client_context_opts!(opts) do
    keys =
      opts
      |> Keyword.take([
        :client_store,
        :provider,
        :client_id,
        :client_secret,
        :client_context_opts
      ])
      |> Keyword.keys()

    # check client context exclusive opts
    if keys -- [:provider, :client_id, :client_secret, :client_context_opts] != [] and
         keys -- [:client_store] != [] do
      raise ArgumentError,
            "Invalid options: #{inspect(opts)}, you should either set :provider, :client_id, :client_secret and :client_context_opts or :client_store"
    end

    opts
  end

  @spec add_csrf_payload(state :: String.t()) :: String.t()
  def add_csrf_payload(state) do
    authenticity_payload = 31 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
    state = if is_binary(state), do: "#{state_authenticity_separator()}#{state}", else: ""
    "#{authenticity_payload}#{state}"
  end

  @spec remove_csrf_payload(state :: String.t()) :: String.t() | nil
  def remove_csrf_payload(authed_state) do
    case String.split(authed_state, state_authenticity_separator(), parts: 2) do
      [_auth_payload] -> nil
      [_auth_payload, state] -> state
    end
  end

  @spec state_authenticity_separator() :: String.t()
  defp state_authenticity_separator, do: "<>"
end
