defmodule Oidcc.Plug.UtilsTest do
  # set to false because we're using mocks
  use ExUnit.Case, async: false

  import Plug.Test
  import Mock

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
      with_mock Oidcc.ClientContext,
        from_configuration_worker: fn :provider_id, "client_id", "client_secret", %{} ->
          expect_result
        end do
        conn = conn(:get, "/")
        assert Utils.get_client_context(conn, opts) == expect_result
      end
    end

    test "can get client context from client_store" do
      defmodule TestClientStore do
        @behaviour Oidcc.Plug.ClientStore

        @impl true
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
      with_mock Oidcc.ClientContext,
        from_configuration_worker: fn :provider_id, "dynamic_id", "dynamic_secret", %{} ->
          expect_result
        end do
        conn = conn(:get, "/")
        assert Utils.get_client_context(conn, opts) == expect_result
      end
    end
  end

  describe "get_refresh_jwks_fun/1" do
    test "uses oidcc_jwt_util for provider configuration" do
      refresh_fun = :test_refresh_fun

      with_mock :oidcc_jwt_util,
        refresh_jwks_fun: fn provider_id ->
          assert provider_id == :test_provider
          refresh_fun
        end do
        opts = [provider: :test_provider]
        assert Utils.get_refresh_jwks_fun(opts) == refresh_fun
      end
    end

    test "returns nil when client_store doesn't implement refresh_jwks" do
      defmodule ClientStoreWithoutRefresh do
        @behaviour Oidcc.Plug.ClientStore

        @impl true
        def get_client_context(_conn), do: {:ok, %{}}
      end

      opts = [client_store: ClientStoreWithoutRefresh]

      assert Utils.get_refresh_jwks_fun(opts) == nil
    end

    test "returns client_store.refresh_jwks function when implemented" do
      defmodule ClientStoreWithRefresh do
        @behaviour Oidcc.Plug.ClientStore

        @impl true
        def get_client_context(_conn), do: {:ok, %{}}

        @impl true
        def refresh_jwks(arg), do: {:refreshed, arg}
      end

      opts = [client_store: ClientStoreWithRefresh]

      refresh_fun = Utils.get_refresh_jwks_fun(opts)
      assert is_function(refresh_fun, 1)
      assert refresh_fun.(:test_arg) == {:refreshed, :test_arg}
    end
  end
end
