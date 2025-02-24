defmodule Oidcc.Plug.AuthorizationCallbackTest do
  use ExUnit.Case, async: false
  use Plug.Test

  import Mock

  alias Oidcc.ClientContext
  alias Oidcc.Plug.AuthorizationCallback
  alias Oidcc.Plug.Authorize
  alias Oidcc.ProviderConfiguration

  doctest AuthorizationCallback

  setup_with_mocks([
    {Oidcc.ClientContext, [:passthrough],
     [
       from_configuration_worker: fn _provider, _client_id, _client_secret, _opts ->
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
       end
     ]}
  ]) do
    :ok
  end

  describe inspect(&Authorize.call/2) do
    test "successful retrieve" do
      with_mocks [
        {Oidcc.Token, [],
         retrieve: fn "code",
                      _client_context,
                      %{
                        redirect_uri: "http://localhost:8080/oidc/return",
                        nonce: _nonce,
                        refresh_jwks: _refresh_fun
                      } ->
           {:ok, :token}
         end},
        {Oidcc.Userinfo, [],
         retrieve: fn :token, _client_context, %{} ->
           {:ok, %{"sub" => "sub"}}
         end}
      ] do
        opts =
          AuthorizationCallback.init(
            provider: ProviderName,
            client_id: fn -> "client_id" end,
            client_secret: "client_secret",
            redirect_uri: "http://localhost:8080/oidc/return"
          )

        assert %{
                 halted: false,
                 private: %{
                   Oidcc.Plug.AuthorizationCallback => {:ok, {:token, %{"sub" => "sub"}}}
                 }
               } =
                 "get"
                 |> conn("/", %{"code" => "code"})
                 |> Plug.Test.init_test_session(%{
                   Authorize.get_session_name() => %{
                     nonce: "nonce",
                     peer_ip: {127, 0, 0, 1},
                     useragent: "useragent",
                     pkce_verifier: "pkce_verifier",
                     state_verifier: 0
                   }
                 })
                 |> put_req_header("user-agent", "useragent")
                 |> AuthorizationCallback.call(opts)
      end
    end

    test_with_mock "successful retrieve without userinfo", %{}, Oidcc.Token, [],
      retrieve: fn "code",
                   _client_context,
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
                   pkce_verifier: "pkce_verifier",
                   state_verifier: 0
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
                   pkce_verifier: "pkce_verifier",
                   state_verifier: 0
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
                   pkce_verifier: "pkce_verifier",
                   state_verifier: 0
                 }
               })
               |> put_req_header("user-agent", "useragent")
               |> AuthorizationCallback.call(opts)
    end

    test "allows mismatch if disabled" do
      with_mocks [
        {Oidcc.Token, [],
         retrieve: fn "code",
                      _client_context,
                      %{redirect_uri: "http://localhost:8080/oidc/return", nonce: _nonce} ->
           {:ok, :token}
         end},
        {Oidcc.Userinfo, [],
         retrieve: fn :token, _client_context, %{} ->
           {:ok, %{"sub" => "sub"}}
         end}
      ] do
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
                 private: %{
                   Oidcc.Plug.AuthorizationCallback => {:ok, {:token, %{"sub" => "sub"}}}
                 }
               } =
                 "get"
                 |> conn("/", %{"code" => "code"})
                 |> Plug.Test.init_test_session(%{
                   Authorize.get_session_name() => %{
                     nonce: "nonce",
                     peer_ip: {127, 0, 0, 2},
                     useragent: "useragent",
                     pkce_verifier: "pkce_verifier",
                     state_verifier: 0
                   }
                 })
                 |> put_req_header("user-agent", "other useragent")
                 |> AuthorizationCallback.call(opts)
      end
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
                   pkce_verifier: "pkce_verifier",
                   state_verifier: 0
                 }
               })
               |> put_req_header("user-agent", "useragent")
               |> AuthorizationCallback.call(opts)
    end

    test "state mismatch" do
      with_mocks [
        {Oidcc.Token, [],
         retrieve: fn "code",
                      _client_context,
                      %{redirect_uri: "http://localhost:8080/oidc/return", nonce: _nonce} ->
           {:ok, :token}
         end},
        {Oidcc.Userinfo, [],
         retrieve: fn :token, _client_context, %{} ->
           {:ok, %{"sub" => "sub"}}
         end}
      ] do
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
                   Oidcc.Plug.AuthorizationCallback => {:ok, {:token, %{"sub" => "sub"}}}
                 }
               } =
                 "get"
                 |> conn("/", %{"code" => "code", "state" => "state"})
                 |> Plug.Test.init_test_session(%{
                   Authorize.get_session_name() => %{
                     nonce: "nonce",
                     peer_ip: {127, 0, 0, 1},
                     useragent: "useragent",
                     pkce_verifier: "pkce_verifier",
                     state_verifier: :erlang.phash2("state")
                   }
                 })
                 |> put_req_header("user-agent", "useragent")
                 |> AuthorizationCallback.call(opts)

        assert %{
                 halted: false,
                 private: %{Oidcc.Plug.AuthorizationCallback => {:error, :state_not_verified}}
               } =
                 "get"
                 |> conn("/", %{"code" => "code", "state" => "state"})
                 |> Plug.Test.init_test_session(%{
                   Authorize.get_session_name() => %{
                     nonce: "nonce",
                     peer_ip: {127, 0, 0, 1},
                     useragent: "useragent",
                     pkce_verifier: "pkce_verifier",
                     state_verifier: 0
                   }
                 })
                 |> put_req_header("user-agent", "useragent")
                 |> AuthorizationCallback.call(opts)

        assert %{
                 halted: false,
                 private: %{
                   Oidcc.Plug.AuthorizationCallback => {:ok, {:token, %{"sub" => "sub"}}}
                 }
               } =
                 "get"
                 |> conn("/", %{"code" => "code"})
                 |> Plug.Test.init_test_session(%{
                   Authorize.get_session_name() => %{
                     nonce: "nonce",
                     peer_ip: {127, 0, 0, 1},
                     useragent: "useragent",
                     pkce_verifier: "pkce_verifier",
                     state_verifier: 0
                   }
                 })
                 |> put_req_header("user-agent", "useragent")
                 |> AuthorizationCallback.call(opts)
      end
    end

    test "passes none alg with userinfo" do
      with_mocks [
        {Oidcc.Token, [],
         retrieve: fn "code",
                      _client_context,
                      %{redirect_uri: "http://localhost:8080/oidc/return", nonce: _nonce} ->
           {:error, {:none_alg_used, :token}}
         end},
        {Oidcc.Userinfo, [],
         retrieve: fn :token, _client_context, %{} ->
           {:ok, %{"sub" => "sub"}}
         end}
      ] do
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
                   Oidcc.Plug.AuthorizationCallback => {:ok, {:token, %{"sub" => "sub"}}}
                 }
               } =
                 "get"
                 |> conn("/", %{"code" => "code"})
                 |> Plug.Test.init_test_session(%{
                   Authorize.get_session_name() => %{
                     nonce: "nonce",
                     peer_ip: {127, 0, 0, 1},
                     useragent: "useragent",
                     pkce_verifier: "pkce_verifier",
                     state_verifier: 0
                   }
                 })
                 |> put_req_header("user-agent", "useragent")
                 |> AuthorizationCallback.call(opts)
      end
    end
  end

  test_with_mock "fails none alg without userinfo", %{}, Oidcc.Token, [],
    retrieve: fn "code",
                 _client_context,
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
                 pkce_verifier: "pkce_verifier",
                 state_verifier: 0
               }
             })
             |> put_req_header("user-agent", "useragent")
             |> AuthorizationCallback.call(opts)
  end

  test_with_mock "relays errors", %{}, Oidcc.Token, [],
    retrieve: fn "code",
                 _client_context,
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

  test "no session" do
    with_mocks [
      {Oidcc.Token, [],
       retrieve: fn
         "code", _client_context, opts ->
           refute Map.has_key?(opts, :pkce_verifier)
           {:ok, :token}
           {:ok, :token}
       end},
      {Oidcc.Userinfo, [],
       retrieve: fn :token, _client_context, %{} ->
         {:ok, %{"sub" => "sub"}}
       end}
    ] do
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
                 Oidcc.Plug.AuthorizationCallback => {:ok, {:token, %{"sub" => "sub"}}}
               }
             } =
               "get"
               |> conn("/", %{"code" => "code"})
               |> Plug.Test.init_test_session(%{})
               |> put_req_header("user-agent", "useragent")
               |> AuthorizationCallback.call(opts)
    end
  end
end
