defmodule Oidcc.Plug.IntrospectTokenTest do
  use ExUnit.Case, async: false
  use Plug.Test

  import Mock

  alias Oidcc.Plug.ExtractAuthorization
  alias Oidcc.Plug.IntrospectToken

  doctest IntrospectToken

  describe inspect(&IntrospectToken.call/2) do
    test_with_mock "validates token using introspection", %{}, Oidcc, [],
      introspect_token: fn "token", ProviderName, "client_id", "client_secret", %{} ->
        {:ok, %Oidcc.TokenIntrospection{active: true}}
      end do
      opts =
        IntrospectToken.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret"
        )

      assert %{
               halted: false,
               private: %{IntrospectToken => %Oidcc.TokenIntrospection{active: true}}
             } =
               "get"
               |> conn("/", "")
               |> put_private(ExtractAuthorization, "token")
               |> IntrospectToken.call(opts)
    end

    test "skips without token" do
      opts =
        IntrospectToken.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret"
        )

      assert %{halted: false} =
               "get"
               |> conn("/", "")
               |> put_private(ExtractAuthorization, nil)
               |> IntrospectToken.call(opts)
    end

    test "errors without ExtractAuthorization" do
      opts =
        IntrospectToken.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret"
        )

      assert_raise RuntimeError, fn ->
        "get"
        |> conn("/", "")
        |> IntrospectToken.call(opts)
      end
    end

    test_with_mock "relays introspection error", %{}, Oidcc, [],
      introspect_token: fn "token", ProviderName, "client_id", "client_secret", %{} ->
        {:error, :reason}
      end do
      opts =
        IntrospectToken.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret"
        )

      assert_raise IntrospectToken.Error, fn ->
        "get"
        |> conn("/", "")
        |> put_private(ExtractAuthorization, "token")
        |> IntrospectToken.call(opts)
      end
    end

    test_with_mock "sends error response with inactive token", %{}, Oidcc, [],
      introspect_token: fn "token", ProviderName, "client_id", "client_secret", %{} ->
        {:ok, %Oidcc.TokenIntrospection{active: false}}
      end do
      opts =
        IntrospectToken.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret"
        )

      assert %{
               halted: true,
               status: 401,
               private: %{IntrospectToken => %Oidcc.TokenIntrospection{active: false}},
               resp_body: "The provided token is inactive"
             } =
               "get"
               |> conn("/", "")
               |> put_private(ExtractAuthorization, "token")
               |> IntrospectToken.call(opts)
    end

    test_with_mock "can customize inactive token response", %{}, Oidcc, [],
      introspect_token: fn "token", ProviderName, "client_id", "client_secret", %{} ->
        {:ok, %Oidcc.TokenIntrospection{active: false}}
      end do
      opts =
        IntrospectToken.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret",
          send_inactive_token_response: fn conn, _introspection ->
            Plug.Conn.send_resp(conn, 500, "invalid")
          end
        )

      assert %{
               status: 500,
               private: %{IntrospectToken => %Oidcc.TokenIntrospection{active: false}},
               resp_body: "invalid"
             } =
               "get"
               |> conn("/", "")
               |> put_private(ExtractAuthorization, "token")
               |> IntrospectToken.call(opts)
    end

    test "uses cache if provided and found" do
      opts =
        IntrospectToken.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret",
          cache: fn _conn, "token" ->
            {:ok, %Oidcc.TokenIntrospection{active: true}}
          end
        )

      assert %{
               halted: false,
               private: %{IntrospectToken => %Oidcc.TokenIntrospection{active: true}}
             } =
               "get"
               |> conn("/", "")
               |> put_private(ExtractAuthorization, "token")
               |> IntrospectToken.call(opts)
    end
  end

  test "integration test" do
    pid =
      start_link_supervised!(
        {Oidcc.ProviderConfiguration.Worker, %{issuer: "https://erlef-test-w4a8z2.zitadel.cloud"}}
      )

    %{"key" => key, "keyId" => kid, "userId" => subject} =
      :oidcc_plug
      |> Application.app_dir("priv/test/fixtures/zitadel-jwt-profile.json")
      |> File.read!()
      |> JOSE.decode()

    %{"clientId" => client_id, "clientSecret" => client_secret, "projectId" => project_id} =
      :oidcc_plug
      |> Application.app_dir("priv/test/fixtures/zitadel-client.json")
      |> File.read!()
      |> JOSE.decode()

    jwk = JOSE.JWK.from_pem(key)

    {:ok, %Oidcc.Token{access: %Oidcc.Token.Access{token: access_token}}} =
      Oidcc.jwt_profile_token(
        subject,
        pid,
        client_id,
        client_secret,
        jwk,
        %{scope: ["urn:zitadel:iam:org:project:id:#{project_id}:aud"], kid: kid}
      )

    opts =
      IntrospectToken.init(
        provider: pid,
        client_id: client_id,
        client_secret: client_secret
      )

    assert %{
             halted: false,
             private: %{
               IntrospectToken => %Oidcc.TokenIntrospection{active: true, client_id: ^client_id}
             }
           } =
             "get"
             |> conn("/", "")
             |> put_private(ExtractAuthorization, access_token)
             |> IntrospectToken.call(opts)
  end
end
