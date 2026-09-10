defmodule Oidcc.Plug.AuthorizationCallbackTest do
  use ExUnit.Case, async: false

  import Mock
  import Plug.Conn
  import Plug.Test

  alias Oidcc.ClientContext
  alias Oidcc.Plug.AuthorizationCallback
  alias Oidcc.Plug.Authorize
  alias Oidcc.Plug.ClientStore
  alias Oidcc.ProviderConfiguration

  doctest AuthorizationCallback

  setup_with_mocks([
    {ClientContext, [:passthrough],
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

  describe inspect(&AuthorizationCallback.call/2) do
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
                   AuthorizationCallback => {:ok, {:token, %{"sub" => "sub"}}}
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
      end
    end

    test "passes the audience to the token request" do
      with_mocks [
        {Oidcc.Token, [],
         retrieve: fn "code", _client_context, %{audience: "https://example.com/oauth2/token"} ->
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
            redirect_uri: "http://localhost:8080/oidc/return",
            audience: "https://example.com/oauth2/token"
          )

        assert %{
                 halted: false,
                 private: %{
                   AuthorizationCallback => {:ok, {:token, %{"sub" => "sub"}}}
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
      end
    end

    test "successful retrieve with dynamic config" do
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
            client_id: fn %Plug.Conn{} -> "client_id" end,
            client_secret: fn %Plug.Conn{} -> "client_secret" end,
            redirect_uri: fn %Plug.Conn{} -> "http://localhost:8080/oidc/return" end
          )

        assert %{
                 halted: false,
                 private: %{
                   AuthorizationCallback => {:ok, {:token, %{"sub" => "sub"}}}
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
      end
    end

    test_with_mock "successful retrieve without userinfo", %{}, Oidcc.Token, [],
      retrieve: fn "code", _client_context, %{redirect_uri: "http://localhost:8080/oidc/return", nonce: _nonce} ->
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
               private: %{AuthorizationCallback => {:ok, {:token, nil}}}
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
    end

    test "successful retrieve with CSRF state" do
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
                   AuthorizationCallback => {:ok, {:token, %{"sub" => "sub"}}},
                   Authorize.State => "state"
                 }
               } =
                 "get"
                 |> conn("/", %{"code" => "code", "state" => "1234<>state"})
                 |> Plug.Test.init_test_session(%{
                   Authorize.get_session_name() => %{
                     nonce: "nonce",
                     peer_ip: {127, 0, 0, 1},
                     useragent: "useragent",
                     pkce_verifier: "pkce_verifier",
                     state_verifier: :erlang.phash2("1234<>state")
                   }
                 })
                 |> put_req_header("user-agent", "useragent")
                 |> AuthorizationCallback.call(opts)
      end
    end

    test "successful retrieve with CSRF only" do
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
                   AuthorizationCallback => {:ok, {:token, %{"sub" => "sub"}}},
                   Authorize.State => nil
                 }
               } =
                 "get"
                 |> conn("/", %{"code" => "code", "state" => "1234"})
                 |> Plug.Test.init_test_session(%{
                   Authorize.get_session_name() => %{
                     nonce: "nonce",
                     peer_ip: {127, 0, 0, 1},
                     useragent: "useragent",
                     pkce_verifier: "pkce_verifier",
                     state_verifier: :erlang.phash2("1234")
                   }
                 })
                 |> put_req_header("user-agent", "useragent")
                 |> AuthorizationCallback.call(opts)
      end
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
               private: %{AuthorizationCallback => {:error, :useragent_mismatch}}
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

    test "useragent mismatch is detected for a session written by Authorize" do
      authorize_opts =
        Authorize.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret",
          redirect_uri: "http://localhost:8080/oidc/return"
        )

      callback_opts =
        AuthorizationCallback.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret",
          redirect_uri: "http://localhost:8080/oidc/return"
        )

      # Drive the real Authorize plug so the session is built the way production
      # builds it, rather than hand-crafting it.
      authorize_conn =
        with_mock Oidcc.Authorization, [],
          create_redirect_url: fn _client_context, _opts -> {:ok, "http://example.com"} end do
          "get"
          |> conn("/", "")
          |> Plug.Test.init_test_session(%{})
          |> put_req_header("user-agent", "victim useragent")
          |> Authorize.call(authorize_opts)
        end

      session = get_session(authorize_conn, Authorize.get_session_name())

      # Token retrieval is mocked so that reaching it at all means the useragent
      # check failed to reject the request.
      with_mocks [
        {Oidcc.Token, [], retrieve: fn "code", _client_context, _opts -> {:ok, :token} end},
        {Oidcc.Userinfo, [], retrieve: fn :token, _client_context, %{} -> {:ok, %{"sub" => "sub"}} end}
      ] do
        # Replaying the callback from a different user agent must be rejected.
        assert %{
                 halted: false,
                 private: %{AuthorizationCallback => {:error, :useragent_mismatch}}
               } =
                 "get"
                 |> conn("/", %{"code" => "code"})
                 |> Plug.Test.init_test_session(%{Authorize.get_session_name() => session})
                 |> put_req_header("user-agent", "attacker useragent")
                 |> AuthorizationCallback.call(callback_opts)
      end
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
               private: %{AuthorizationCallback => {:error, :peer_ip_mismatch}}
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

    test "peer_ip match on remote_ip only" do
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
         end}
      ] do
        opts =
          AuthorizationCallback.init(
            provider: ProviderName,
            client_id: fn -> "client_id" end,
            client_secret: "client_secret",
            redirect_uri: "http://localhost:8080/oidc/return",
            retrieve_userinfo: false
          )

        conn =
          "get"
          |> conn("/", %{"code" => "code", "state" => "state"})
          |> put_req_header("x-forwarded-for", "10.0.0.1")
          |> Plug.RewriteOn.call(Plug.RewriteOn.init([:x_forwarded_for]))

        assert %{
                 halted: false,
                 private: %{
                   AuthorizationCallback => {:ok, {:token, nil}}
                 }
               } =
                 conn
                 |> Plug.Test.init_test_session(%{
                   Authorize.get_session_name() => %{
                     nonce: "nonce",
                     peer_ip: {10, 0, 0, 1},
                     useragent: "useragent",
                     pkce_verifier: "pkce_verifier",
                     state_verifier: :erlang.phash2("state")
                   }
                 })
                 |> put_req_header("user-agent", "useragent")
                 |> AuthorizationCallback.call(opts)
      end
    end

    test "allows mismatch if disabled" do
      with_mocks [
        {Oidcc.Token, [],
         retrieve: fn "code", _client_context, %{redirect_uri: "http://localhost:8080/oidc/return", nonce: _nonce} ->
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
                   AuthorizationCallback => {:ok, {:token, %{"sub" => "sub"}}}
                 }
               } =
                 "get"
                 |> conn("/", %{"code" => "code", "state" => "state"})
                 |> Plug.Test.init_test_session(%{
                   Authorize.get_session_name() => %{
                     nonce: "nonce",
                     peer_ip: {127, 0, 0, 2},
                     useragent: "useragent",
                     pkce_verifier: "pkce_verifier",
                     state_verifier: :erlang.phash2("state")
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
                 AuthorizationCallback => {:error, {:missing_request_param, "code"}}
               }
             } =
               "get"
               |> conn("/", %{"state" => "state"})
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
    end

    test "state mismatch" do
      with_mocks [
        {Oidcc.Token, [],
         retrieve: fn "code", _client_context, %{redirect_uri: "http://localhost:8080/oidc/return", nonce: _nonce} ->
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
                   AuthorizationCallback => {:ok, {:token, %{"sub" => "sub"}}}
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
                 private: %{AuthorizationCallback => {:error, :state_not_verified}}
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

        # a verifier is in the session, so omitting the state does not skip the
        # check
        assert %{
                 halted: false,
                 private: %{AuthorizationCallback => {:error, :state_not_verified}}
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

    test "non binary state" do
      opts =
        AuthorizationCallback.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret",
          redirect_uri: "http://localhost:8080/oidc/return",
          retrieve_userinfo: false
        )

      # a param can be a list or a map, ?state[]=a or ?state[a]=b
      for state <- [["a", "b"], %{"a" => "b"}] do
        assert %{
                 halted: false,
                 private: %{AuthorizationCallback => {:error, :state_not_verified}}
               } =
                 "get"
                 |> conn("/", %{"code" => "code", "state" => state})
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
      end
    end

    test "incomplete authorize session" do
      opts =
        AuthorizationCallback.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret",
          redirect_uri: "http://localhost:8080/oidc/return",
          retrieve_userinfo: false
        )

      for session <- [%{}, %{nonce: "nonce"}, %{state_verifier: nil}] do
        assert %{
                 halted: false,
                 private: %{
                   AuthorizationCallback => {:error, :missing_authorize_session}
                 }
               } =
                 "get"
                 |> conn("/", %{"code" => "code", "state" => "state"})
                 |> Plug.Test.init_test_session(%{
                   Authorize.get_session_name() => session
                 })
                 |> put_req_header("user-agent", "useragent")
                 |> AuthorizationCallback.call(opts)
      end
    end

    test "passes none alg with userinfo" do
      with_mocks [
        {Oidcc.Token, [],
         retrieve: fn "code", _client_context, %{redirect_uri: "http://localhost:8080/oidc/return", nonce: _nonce} ->
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
                   AuthorizationCallback => {:ok, {:token, %{"sub" => "sub"}}}
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
      end
    end
  end

  test_with_mock "fails none alg without userinfo", %{}, Oidcc.Token, [],
    retrieve: fn "code", _client_context, %{redirect_uri: "http://localhost:8080/oidc/return", nonce: _nonce} ->
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
             private: %{AuthorizationCallback => {:error, {:none_alg_used, :token}}}
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
  end

  test_with_mock "relays errors", %{}, Oidcc.Token, [],
    retrieve: fn "code", _client_context, %{redirect_uri: "http://localhost:8080/oidc/return", nonce: _nonce} ->
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
             private: %{AuthorizationCallback => {:error, :provider_not_ready}}
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
  end

  describe "session and state validation (GHSA-fg66-w5gp-22cr)" do
    test "rejects a callback without an authorize session" do
      with_mock Oidcc.Token, [], retrieve: fn _code, _client_context, _opts -> {:ok, :token} end do
        opts =
          AuthorizationCallback.init(
            provider: ProviderName,
            client_id: "client_id",
            client_secret: "client_secret",
            redirect_uri: "http://localhost:8080/oidc/return",
            retrieve_userinfo: false
          )

        assert %{
                 private: %{
                   AuthorizationCallback => {:error, :missing_authorize_session}
                 }
               } =
                 "get"
                 |> conn("/", %{"code" => "attacker_code"})
                 |> Plug.Test.init_test_session(%{})
                 |> put_req_header("user-agent", "useragent")
                 |> AuthorizationCallback.call(opts)

        assert_not_called(Oidcc.Token.retrieve(:_, :_, :_))
      end
    end

    test "rejects a callback that omits the state when a verifier is in the session" do
      with_mock Oidcc.Token, [], retrieve: fn _code, _client_context, _opts -> {:ok, :token} end do
        opts =
          AuthorizationCallback.init(
            provider: ProviderName,
            client_id: "client_id",
            client_secret: "client_secret",
            redirect_uri: "http://localhost:8080/oidc/return",
            retrieve_userinfo: false
          )

        assert %{
                 private: %{AuthorizationCallback => {:error, :state_not_verified}}
               } =
                 "get"
                 |> conn("/", %{"code" => "attacker_code"})
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

        assert_not_called(Oidcc.Token.retrieve(:_, :_, :_))
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

    test "retrieves token with client_store" do
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
            client_store: TestClientStore,
            redirect_uri: "http://localhost:8080/oidc/return"
          )

        assert %{
                 halted: false,
                 private: %{
                   AuthorizationCallback => {:ok, {:token, %{"sub" => "sub"}}}
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
      end
    end
  end
end
