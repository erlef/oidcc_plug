defmodule Oidcc.Plug.ClientStore do
  @moduledoc """
  Behaviour for retrieving and managing OpenID Connect client contexts.

  This module defines the callbacks that must be implemented by any client store
  used with the Oidcc.Plug components. A client store is responsible for:

  1. Retrieving the client context from a connection
  2. Optionally refreshing the JSON Web Key Set (JWKS) for a client context

  ## Examples

  ```elixir
  defmodule MyApp.OktaClientStore do
    @behaviour Oidcc.Plug.ClientStore

    alias Oidcc.ClientContext
    alias Oidcc.ProviderConfiguration

    @impl true
    def get_client_context(conn) do
      with email when is_binary(email) <- conn.assigns[:email],
        {:ok, okta_config} <- get_okta_oidc_config(email),
        {:ok,
          {
            %ProviderConfiguration{} = configuration,
            _expiry
          }} <- ProviderConfiguration.load_configuration(okta_config.issuer),
        {:ok, {jwks, _expiry}} <- ProviderConfiguration.load_jwks(configuration.jwks_uri),
        %ClientContext{} = client_context <-
          ClientContext.from_manual(configuration, jwks, okta_config.client_id, okta_config.client_secret) do
        {:ok, client_context}
      end
    end

    defp get_okta_oidc_config(email) do
      # Implementation depends on your application's needs
      # This is just a placeholder
      {:ok, %{issuer: "https://my-domain.okta.com", client_id: "my_client_id", client_secret: "my_client_secret"}}
    end
  end
  ```
  """

  @callback get_client_context(conn :: Plug.Conn.t()) ::
              {:error, term()} | {:ok, Oidcc.ClientContext.t()}

  @callback refresh_jwks(context :: Oidcc.ClientContext.t()) ::
              {:ok, JOSE.JWK.t()} | {:error, term()}

  @optional_callbacks refresh_jwks: 1
end
