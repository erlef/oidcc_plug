# SPDX-FileCopyrightText: 2025 Erlang Ecosystem Foundation
# SPDX-FileCopyrightText: 2025 Matt Enlow
# SPDX-FileCopyrightText: 2025 Yannis Weishaupt
# SPDX-FileCopyrightText: 2026 Mathias Polligkeit
#
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.Plug.UtilsTest do
  # set to false because we're using mocks
  use ExUnit.Case, async: false
  use Mimic

  import Plug.Test

  alias Oidcc.Plug.Utils

  doctest Utils

  describe "validate_client_context_opts!/1" do
    test "allows valid provider configuration" do
      opts = [
        provider: :provider_id,
        client_id: "client_id",
        client_secret: "client_secret",
        client_context_opts: %{}
      ]

      assert Utils.validate_client_context_opts!(opts) == opts
    end

    test "allows client_store configuration" do
      opts = [client_store: MyClientStore]

      assert Utils.validate_client_context_opts!(opts) == opts
    end

    test "raises error on mixed configuration" do
      opts = [
        client_store: MyClientStore,
        provider: :provider_id,
        client_id: "client_id"
      ]

      assert_raise ArgumentError, ~r/Invalid options:.*/, fn ->
        Utils.validate_client_context_opts!(opts)
      end
    end
  end

  describe "get_client_context/2" do
    test "can get client context from configuration worker" do
      expect_result =
        {:ok,
         %Oidcc.ClientContext{
           provider_configuration: %Oidcc.ProviderConfiguration{},
           jwks: %{},
           client_id: "from-config",
           client_secret: "secret",
           client_jwks: :none
         }}

      # Test with regular values
      opts = [
        provider: :provider_id,
        client_id: "client_id",
        client_secret: "client_secret",
        client_context_opts: %{}
      ]

      # Mock the external function call
      stub(Oidcc.ClientContext, :from_configuration_worker, fn :provider_id, "client_id", "client_secret", %{} ->
        expect_result
      end)

      conn = conn(:get, "/")
      assert Utils.get_client_context(conn, opts) == expect_result
    end

    test "can get client context from client_store" do
      defmodule TestClientStore do
        @moduledoc false
        @behaviour Oidcc.Plug.ClientStore

        alias Oidcc.Plug.ClientStore

        @impl ClientStore
        def get_client_context(_conn) do
          {:ok,
           %Oidcc.ClientContext{
             provider_configuration: %Oidcc.ProviderConfiguration{},
             jwks: %{},
             client_id: "test-client",
             client_secret: "secret",
             client_jwks: :none
           }}
        end
      end

      conn = conn(:get, "/")
      opts = [client_store: TestClientStore]

      {:ok, client_context} = Utils.get_client_context(conn, opts)
      assert client_context.client_id == "test-client"
      assert client_context.client_secret == "secret"
    end

    test "evaluates function config values" do
      # Create a mock client context
      mock_context = %Oidcc.ClientContext{
        provider_configuration: %Oidcc.ProviderConfiguration{},
        jwks: %{},
        client_id: "dynamic-config",
        client_secret: "secret",
        client_jwks: :none
      }

      expect_result = {:ok, mock_context}

      opts = [
        provider: :provider_id,
        client_id: fn -> "dynamic_id" end,
        client_secret: fn -> "dynamic_secret" end,
        client_context_opts: fn -> %{} end
      ]

      # Mock the external function call
      stub(Oidcc.ClientContext, :from_configuration_worker, fn :provider_id, "dynamic_id", "dynamic_secret", %{} ->
        expect_result
      end)

      conn = conn(:get, "/")
      assert Utils.get_client_context(conn, opts) == expect_result
    end
  end

  defmodule ClientStoreWithoutRefresh do
    @moduledoc false
    @behaviour Oidcc.Plug.ClientStore

    alias Oidcc.Plug.ClientStore

    @impl ClientStore
    def get_client_context(_conn), do: {:ok, %{}}
  end

  defmodule ClientStoreWithRefresh do
    @moduledoc false
    @behaviour Oidcc.Plug.ClientStore

    alias Oidcc.Plug.ClientStore

    @impl ClientStore
    def get_client_context(_conn), do: {:ok, %{}}

    @impl ClientStore
    def refresh_jwks(context), do: {:refreshed, context}
  end

  describe "put_refresh_jwks/3" do
    test "uses oidcc_jwt_util for provider configuration" do
      refresh_fun = :test_refresh_fun

      stub(:oidcc_jwt_util, :refresh_jwks_fun, fn provider_id ->
        assert provider_id == :test_provider
        refresh_fun
      end)

      opts = [provider: :test_provider]

      assert Utils.put_refresh_jwks(%{}, :client_context, opts) == %{refresh_jwks: refresh_fun}
    end

    test "adds a fun with the arity oidcc calls it with" do
      opts = [client_store: ClientStoreWithRefresh]

      assert %{refresh_jwks: refresh_jwks} = Utils.put_refresh_jwks(%{}, :client_context, opts)

      # oidcc invokes the refresh fun as fun(jwks, kid)
      assert is_function(refresh_jwks, 2)
    end

    test "passes the client context to client_store.refresh_jwks/1" do
      opts = [client_store: ClientStoreWithRefresh]

      %{refresh_jwks: refresh_jwks} = Utils.put_refresh_jwks(%{}, :client_context, opts)

      assert refresh_jwks.(:stale_jwks, "unknown_kid") == {:refreshed, :client_context}
    end

    test "omits the key for a client_store without the callback" do
      opts = [client_store: ClientStoreWithoutRefresh]

      # oidcc only skips the refresh when the key is absent, so it must not be
      # set to nil
      assert Utils.put_refresh_jwks(%{}, :client_context, opts) == %{}
    end

    test "keeps existing keys" do
      opts = [client_store: ClientStoreWithoutRefresh]

      assert Utils.put_refresh_jwks(%{nonce: :any}, :client_context, opts) == %{nonce: :any}
    end
  end
end
