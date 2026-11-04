# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-FileCopyrightText: 2025 Enzo Baldisserri
# SPDX-FileCopyrightText: 2025 Matt Enlow
# SPDX-FileCopyrightText: 2025 Yannis Weishaupt
# SPDX-FileCopyrightText: 2026 Benjamin Milde
#
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.Plug.AuthorizeTest do
  use ExUnit.Case, async: false
  use Mimic

  import Plug.Conn
  import Plug.Test

  alias Oidcc.ClientContext
  alias Oidcc.Plug.Authorize
  alias Oidcc.Plug.ClientStore
  alias Oidcc.ProviderConfiguration

  doctest Authorize

  setup do
    stub(ClientContext, :from_configuration_worker, fn _provider, _client_id, _client_secret, _opts ->
      {:ok, provider_configuration} =
        ProviderConfiguration.decode_configuration(%{
          "issuer" => "https://example.com",
          "authorization_endpoint" => "https://example.com/auth",
          "jwks_uri" => "https://example.com/jwks",
          "scopes_supported" => ["openid"],
          "response_types_supported" => ["code"],
          "subject_types_supported" => ["public"],
          "id_token_signing_alg_values_supported" => ["RS256"]
        })

      jwks = JOSE.JWK.generate_key({:oct, 64})

      {:ok,
       ClientContext.from_manual(
         provider_configuration,
         jwks,
         "client_id",
         "client_secret",
         %{}
       )}
    end)

    :ok
  end

  describe inspect(&Authorize.call/2) do
    test "successful redirect" do
      stub(Oidcc.Authorization, :create_redirect_url, fn
        _client_context,
        %{
          redirect_uri: "http://localhost:8080/oidc/return",
          nonce: _nonce
        } ->
          {:ok, "http://example.com"}
      end)

      opts =
        Authorize.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret",
          redirect_uri: "http://localhost:8080/oidc/return"
        )

      assert %{
               halted: false,
               status: 302
             } =
               conn =
               "get"
               |> conn("/", "")
               |> Plug.Test.init_test_session(%{})
               |> Authorize.call(opts)

      assert ["http://example.com"] = get_resp_header(conn, "location")
    end

    test "manual redirect" do
      stub(Oidcc.Authorization, :create_redirect_url, fn
        _client_context,
        %{
          redirect_uri: "http://localhost:8080/oidc/return",
          nonce: _nonce
        } ->
          {:ok, "http://example.com"}
      end)

      opts =
        Authorize.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret",
          redirect_uri: "http://localhost:8080/oidc/return",
          redirect_mode: :manual
        )

      assert %{
               halted: false,
               status: nil,
               private: %{
                 Authorize => "http://example.com"
               }
             } =
               conn =
               "get"
               |> conn("/", "")
               |> Plug.Test.init_test_session(%{})
               |> Authorize.call(opts)

      assert [] = get_resp_header(conn, "location")
    end

    test "stores useragent in session" do
      stub(Oidcc.Authorization, :create_redirect_url, fn
        _client_context,
        %{
          redirect_uri: "http://localhost:8080/oidc/return",
          nonce: _nonce
        } ->
          {:ok, "http://example.com"}
      end)

      opts =
        Authorize.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret",
          redirect_uri: "http://localhost:8080/oidc/return"
        )

      conn =
        "get"
        |> conn("/", "")
        |> Plug.Test.init_test_session(%{})
        |> put_req_header("user-agent", "test useragent")
        |> Authorize.call(opts)

      assert %{useragent: "test useragent"} = get_session(conn, Authorize.get_session_name())
    end

    test "error handling" do
      stub(Oidcc.Authorization, :create_redirect_url, fn
        _client_context,
        %{
          redirect_uri: "http://localhost:8080/oidc/return",
          nonce: _nonce
        } ->
          {:error, :provider_not_ready}
      end)

      opts =
        Authorize.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret",
          redirect_uri: "http://localhost:8080/oidc/return"
        )

      assert_raise Authorize.Error, fn ->
        "get"
        |> conn("/", "")
        |> Plug.Test.init_test_session(%{})
        |> Authorize.call(opts)
      end
    end
  end

  describe "client_store" do
    defmodule TestClientStore do
      @moduledoc false
      @behaviour ClientStore

      @impl ClientStore
      def get_client_context(_conn) do
        {:ok, provider_configuration} =
          ProviderConfiguration.decode_configuration(%{
            "issuer" => "https://example.com",
            "authorization_endpoint" => "https://example.com/auth",
            "jwks_uri" => "https://example.com/jwks",
            "scopes_supported" => ["openid"],
            "response_types_supported" => ["code"],
            "subject_types_supported" => ["public"],
            "id_token_signing_alg_values_supported" => ["RS256"]
          })

        jwks = JOSE.JWK.generate_key({:oct, 64})

        {:ok,
         ClientContext.from_manual(
           provider_configuration,
           jwks,
           "test_client_id",
           "test_client_secret",
           %{}
         )}
      end

      @impl ClientStore
      def refresh_jwks(_context) do
        jwks = JOSE.JWK.generate_key({:oct, 64})
        {:ok, jwks}
      end
    end

    test "successful redirect with client_store" do
      stub(Oidcc.Authorization, :create_redirect_url, fn
        _client_context,
        %{
          redirect_uri: "http://localhost:8080/oidc/return",
          nonce: _nonce
        } ->
          {:ok, "http://example.com"}
      end)

      opts =
        Authorize.init(
          client_store: TestClientStore,
          redirect_uri: "http://localhost:8080/oidc/return"
        )

      assert %{
               halted: false,
               status: 302
             } =
               conn =
               "get"
               |> conn("/", "")
               |> Plug.Test.init_test_session(%{})
               |> Authorize.call(opts)

      assert ["http://example.com"] = get_resp_header(conn, "location")
    end

    defmodule ErrorClientStore do
      @moduledoc false
      @behaviour ClientStore

      @impl ClientStore
      def get_client_context(_conn) do
        {:error, :client_context_not_found}
      end
    end

    test "handles client_store error" do
      opts =
        Authorize.init(
          client_store: ErrorClientStore,
          redirect_uri: "http://localhost:8080/oidc/return"
        )

      assert_raise Authorize.Error, fn ->
        "get"
        |> conn("/", "")
        |> Plug.Test.init_test_session(%{})
        |> Authorize.call(opts)
      end
    end
  end
end
