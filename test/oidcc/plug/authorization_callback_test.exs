defmodule Oidcc.Plug.AuthorizationCallbackTest do
  use ExUnit.Case, async: false
  use Plug.Test

  import Mock

  alias Oidcc.Plug.AuthorizationCallback
  alias Oidcc.Plug.Authorize

  doctest AuthorizationCallback

  describe inspect(&Authorize.call/2) do
    test_with_mock "successful retrieve", %{}, Oidcc, [],
      retrieve_token: fn "code",
                         ProviderName,
                         "client_id",
                         "client_secret",
                         %{redirect_uri: "http://localhost:8080/oidc/return", nonce: _nonce} ->
        {:ok, :token}
      end,
      retrieve_userinfo: fn :token, ProviderName, "client_id", "client_secret", %{} ->
        {:ok, %{"sub" => "sub"}}
      end do
      opts =
        AuthorizationCallback.init(
          provider: ProviderName,
          client_id: fn -> "client_id" end,
          client_secret: "client_secret",
          redirect_uri: "http://localhost:8080/oidc/return"
        )

      assert %{
               halted: false,
               private: %{Oidcc.Plug.AuthorizationCallback => {:ok, {:token, %{"sub" => "sub"}}}}
             } =
               "get"
               |> conn("/", %{"code" => "code"})
               |> Plug.Test.init_test_session(%{
                 Authorize.get_session_name() => %{
                   nonce: "nonce",
                   peer_ip: {127, 0, 0, 1},
                   useragent: "useragent",
                   pkce_verifier: "pkce_verifier"
                 }
               })
               |> put_req_header("user-agent", "useragent")
               |> AuthorizationCallback.call(opts)
    end

    test_with_mock "successful retrieve without userinfo", %{}, Oidcc, [],
      retrieve_token: fn "code",
                         ProviderName,
                         "client_id",
                         "client_secret",
                         %{redirect_uri: "http://localhost:8080/oidc/return", nonce: _nonce} ->
        {:ok, :token}
      end do
      opts =
        AuthorizationCallback.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret",
          redirect_uri: "http://localhost:8080/oidc/return",
          retrieve_userinfo: false
        )

      assert %{
               halted: false,
               private: %{Oidcc.Plug.AuthorizationCallback => {:ok, {:token, nil}}}
             } =
               "get"
               |> conn("/", %{"code" => "code"})
               |> Plug.Test.init_test_session(%{
                 Authorize.get_session_name() => %{
                   nonce: "nonce",
                   peer_ip: {127, 0, 0, 1},
                   useragent: "useragent",
                   pkce_verifier: "pkce_verifier"
                 }
               })
               |> put_req_header("user-agent", "useragent")
               |> AuthorizationCallback.call(opts)
    end

    test "useragent mismatch" do
      opts =
        AuthorizationCallback.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret",
          redirect_uri: "http://localhost:8080/oidc/return"
        )

      assert %{
               halted: false,
               private: %{Oidcc.Plug.AuthorizationCallback => {:error, :useragent_mismatch}}
             } =
               "get"
               |> conn("/", %{"code" => "code"})
               |> Plug.Test.init_test_session(%{
                 Authorize.get_session_name() => %{
                   nonce: "nonce",
                   peer_ip: {127, 0, 0, 1},
                   useragent: "useragent",
                   pkce_verifier: "pkce_verifier"
                 }
               })
               |> put_req_header("user-agent", "other useragent")
               |> AuthorizationCallback.call(opts)
    end

    test "peer_ip mismatch" do
      opts =
        AuthorizationCallback.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret",
          redirect_uri: "http://localhost:8080/oidc/return"
        )

      assert %{
               halted: false,
               private: %{Oidcc.Plug.AuthorizationCallback => {:error, :peer_ip_mismatch}}
             } =
               "get"
               |> conn("/", %{"code" => "code"})
               |> Plug.Test.init_test_session(%{
                 Authorize.get_session_name() => %{
                   nonce: "nonce",
                   peer_ip: {127, 0, 0, 2},
                   useragent: "useragent",
                   pkce_verifier: "pkce_verifier"
                 }
               })
               |> put_req_header("user-agent", "useragent")
               |> AuthorizationCallback.call(opts)
    end

    test_with_mock "allows mismatch if disabled", %{}, Oidcc, [],
      retrieve_token: fn "code",
                         ProviderName,
                         "client_id",
                         "client_secret",
                         %{redirect_uri: "http://localhost:8080/oidc/return", nonce: _nonce} ->
        {:ok, :token}
      end,
      retrieve_userinfo: fn :token, ProviderName, "client_id", "client_secret", %{} ->
        {:ok, %{"sub" => "sub"}}
      end do
      opts =
        AuthorizationCallback.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret",
          redirect_uri: "http://localhost:8080/oidc/return",
          check_useragent: false,
          check_peer_ip: false
        )

      assert %{
               halted: false,
               private: %{Oidcc.Plug.AuthorizationCallback => {:ok, {:token, %{"sub" => "sub"}}}}
             } =
               "get"
               |> conn("/", %{"code" => "code"})
               |> Plug.Test.init_test_session(%{
                 Authorize.get_session_name() => %{
                   nonce: "nonce",
                   peer_ip: {127, 0, 0, 2},
                   useragent: "useragent",
                   pkce_verifier: "pkce_verifier"
                 }
               })
               |> put_req_header("user-agent", "other useragent")
               |> AuthorizationCallback.call(opts)
    end

    test "missing params" do
      opts =
        AuthorizationCallback.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret",
          redirect_uri: "http://localhost:8080/oidc/return"
        )

      assert %{
               halted: false,
               private: %{
                 Oidcc.Plug.AuthorizationCallback => {:error, {:missing_request_param, "code"}}
               }
             } =
               "get"
               |> conn("/", %{})
               |> Plug.Test.init_test_session(%{
                 Authorize.get_session_name() => %{
                   nonce: "nonce",
                   peer_ip: {127, 0, 0, 1},
                   useragent: "useragent",
                   pkce_verifier: "pkce_verifier"
                 }
               })
               |> put_req_header("user-agent", "useragent")
               |> AuthorizationCallback.call(opts)
    end

    test_with_mock "passes none alg with userinfo", %{}, Oidcc, [],
      retrieve_token: fn "code",
                         ProviderName,
                         "client_id",
                         "client_secret",
                         %{redirect_uri: "http://localhost:8080/oidc/return", nonce: _nonce} ->
        {:error, {:none_alg_used, :token}}
      end,
      retrieve_userinfo: fn :token, ProviderName, "client_id", "client_secret", %{} ->
        {:ok, %{"sub" => "sub"}}
      end do
      opts =
        AuthorizationCallback.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret",
          redirect_uri: "http://localhost:8080/oidc/return"
        )

      assert %{
               halted: false,
               private: %{Oidcc.Plug.AuthorizationCallback => {:ok, {:token, %{"sub" => "sub"}}}}
             } =
               "get"
               |> conn("/", %{"code" => "code"})
               |> Plug.Test.init_test_session(%{
                 Authorize.get_session_name() => %{
                   nonce: "nonce",
                   peer_ip: {127, 0, 0, 1},
                   useragent: "useragent",
                   pkce_verifier: "pkce_verifier"
                 }
               })
               |> put_req_header("user-agent", "useragent")
               |> AuthorizationCallback.call(opts)
    end
  end

  test_with_mock "fails none alg without userinfo", %{}, Oidcc, [],
    retrieve_token: fn "code",
                       ProviderName,
                       "client_id",
                       "client_secret",
                       %{redirect_uri: "http://localhost:8080/oidc/return", nonce: _nonce} ->
      {:error, {:none_alg_used, :token}}
    end do
    opts =
      AuthorizationCallback.init(
        provider: ProviderName,
        client_id: "client_id",
        client_secret: "client_secret",
        redirect_uri: "http://localhost:8080/oidc/return",
        retrieve_userinfo: false
      )

    assert %{
             halted: false,
             private: %{Oidcc.Plug.AuthorizationCallback => {:error, {:none_alg_used, :token}}}
           } =
             "get"
             |> conn("/", %{"code" => "code"})
             |> Plug.Test.init_test_session(%{
               Authorize.get_session_name() => %{
                 nonce: "nonce",
                 peer_ip: {127, 0, 0, 1},
                 useragent: "useragent",
                 pkce_verifier: "pkce_verifier"
               }
             })
             |> put_req_header("user-agent", "useragent")
             |> AuthorizationCallback.call(opts)
  end

  test_with_mock "relays errors", %{}, Oidcc, [],
    retrieve_token: fn "code",
                       ProviderName,
                       "client_id",
                       "client_secret",
                       %{redirect_uri: "http://localhost:8080/oidc/return", nonce: _nonce} ->
      {:error, :provider_not_ready}
    end do
    opts =
      AuthorizationCallback.init(
        provider: ProviderName,
        client_id: "client_id",
        client_secret: "client_secret",
        redirect_uri: "http://localhost:8080/oidc/return"
      )

    assert %{
             halted: false,
             private: %{Oidcc.Plug.AuthorizationCallback => {:error, :provider_not_ready}}
           } =
             "get"
             |> conn("/", %{"code" => "code"})
             |> Plug.Test.init_test_session(%{})
             |> put_req_header("user-agent", "useragent")
             |> AuthorizationCallback.call(opts)
  end
end
