# SPDX-FileCopyrightText: 2025 Erlang Ecosystem Foundation
# SPDX-FileCopyrightText: 2025 Matt Enlow
# SPDX-FileCopyrightText: 2025 Yannis Weishaupt
# SPDX-FileCopyrightText: 2026 Giorgio Primola
# SPDX-FileCopyrightText: 2026 Mathias Polligkeit
# SPDX-FileCopyrightText: 2026 Mathias Wingert
#
# SPDX-License-Identifier: Apache-2.0

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
  Adds the JWKS refresh function to `map`, unless there is none.

  The key is omitted rather than set to `nil` because `oidcc` only skips the
  refresh when the key is absent.
  """
  @spec put_refresh_jwks(map(), ClientContext.t(), Keyword.t()) :: map()
  def put_refresh_jwks(map, client_context, opts) do
    case get_refresh_jwks_fun(client_context, opts) do
      nil -> map
      refresh_jwks -> Map.put(map, :refresh_jwks, refresh_jwks)
    end
  end

  # oidcc calls the refresh function with (jwks, kid), while
  # c:Oidcc.Plug.ClientStore.refresh_jwks/1 takes the client context => the store
  # callback is wrapped rather than captured directly.
  @spec get_refresh_jwks_fun(ClientContext.t(), Keyword.t()) ::
          :oidcc_jwt_util.refresh_jwks_for_unknown_kid_fun() | nil
  defp get_refresh_jwks_fun(client_context, opts) do
    case Keyword.get(opts, :client_store) do
      nil ->
        provider = Keyword.fetch!(opts, :provider)
        :oidcc_jwt_util.refresh_jwks_fun(provider)

      client_store ->
        client_store_refresh_jwks_fun(client_store, client_context)
    end
  end

  @spec client_store_refresh_jwks_fun(module(), ClientContext.t()) ::
          :oidcc_jwt_util.refresh_jwks_for_unknown_kid_fun() | nil
  defp client_store_refresh_jwks_fun(client_store, client_context) do
    Code.ensure_loaded!(client_store)

    if function_exported?(client_store, :refresh_jwks, 1),
      do: fn _jwks, _kid -> refresh_jwks_from_store(client_store, client_context) end
  end

  # The callback returns a JOSE.JWK struct, while oidcc puts the result straight
  # into the client context record => convert it.
  @spec refresh_jwks_from_store(module(), ClientContext.t()) ::
          {:ok, :jose_jwk.key()} | {:error, term()}
  defp refresh_jwks_from_store(client_store, client_context) do
    case client_store.refresh_jwks(client_context) do
      {:ok, %JOSE.JWK{} = jwks} -> {:ok, JOSE.JWK.to_record(jwks)}
      other -> other
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
