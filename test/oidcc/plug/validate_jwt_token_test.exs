defmodule Oidcc.Plug.ValidateJwtTokenTest do
  use ExUnit.Case, async: false
  use Plug.Test

  import Mock

  alias Oidcc.Plug.ExtractAuthorization
  alias Oidcc.Plug.ValidateJwtToken

  doctest ValidateJwtToken

  describe inspect(&ValidateJwtToken.call/2) do
    test "validates token using jwt" do
      with_mocks [
        {Oidcc.ClientContext, [],
         from_configuration_worker: fn ProviderName, "client_id", "client_secret" ->
           {:ok, :client_context}
         end},
        {Oidcc.Token, [],
         validate_id_token: fn "token", :client_context, %{nonce: :any, refresh_jwks: _} ->
           {:ok, %{"sub" => "sub"}}
         end}
      ] do
        opts =
          ValidateJwtToken.init(
            provider: ProviderName,
            client_id: "client_id",
            client_secret: "client_secret"
          )

        assert %{
                 halted: false,
                 private: %{ValidateJwtToken => %{"sub" => "sub"}}
               } =
                 "get"
                 |> conn("/", "")
                 |> put_private(ExtractAuthorization, "token")
                 |> ValidateJwtToken.call(opts)
      end
    end

    test "skips without token" do
      opts =
        ValidateJwtToken.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret"
        )

      assert %{halted: false} =
               "get"
               |> conn("/", "")
               |> put_private(ExtractAuthorization, nil)
               |> ValidateJwtToken.call(opts)
    end

    test "errors without ExtractAuthorization" do
      opts =
        ValidateJwtToken.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret"
        )

      assert_raise RuntimeError, fn ->
        "get"
        |> conn("/", "")
        |> ValidateJwtToken.call(opts)
      end
    end

    test "relays validation error" do
      with_mocks [
        {Oidcc.ClientContext, [],
         from_configuration_worker: fn ProviderName, "client_id", "client_secret" ->
           {:ok, :client_context}
         end},
        {Oidcc.Token, [],
         validate_id_token: fn "token", :client_context, %{nonce: :any, refresh_jwks: _} ->
           {:error, :reason}
         end}
      ] do
        opts =
          ValidateJwtToken.init(
            provider: ProviderName,
            client_id: "client_id",
            client_secret: "client_secret"
          )

        assert_raise ValidateJwtToken.Error, fn ->
          "get"
          |> conn("/", "")
          |> put_private(ExtractAuthorization, "token")
          |> ValidateJwtToken.call(opts)
        end
      end
    end

    test "sends error response with inactive token" do
      with_mocks [
        {Oidcc.ClientContext, [],
         from_configuration_worker: fn ProviderName, "client_id", "client_secret" ->
           {:ok, :client_context}
         end},
        {Oidcc.Token, [],
         validate_id_token: fn "token", :client_context, %{nonce: :any, refresh_jwks: _} ->
           {:error, :token_expired}
         end}
      ] do
        opts =
          ValidateJwtToken.init(
            provider: ProviderName,
            client_id: "client_id",
            client_secret: "client_secret"
          )

        assert %{
                 halted: true,
                 status: 401,
                 private: %{ValidateJwtToken => nil},
                 resp_body: "The provided token is inactive"
               } =
                 "get"
                 |> conn("/", "")
                 |> put_private(ExtractAuthorization, "token")
                 |> ValidateJwtToken.call(opts)
      end
    end

    test "can customize inactive token response" do
      with_mocks [
        {Oidcc.ClientContext, [],
         from_configuration_worker: fn ProviderName, "client_id", "client_secret" ->
           {:ok, :client_context}
         end},
        {Oidcc.Token, [],
         validate_id_token: fn "token", :client_context, %{nonce: :any, refresh_jwks: _} ->
           {:error, :token_expired}
         end}
      ] do
        opts =
          ValidateJwtToken.init(
            provider: ProviderName,
            client_id: "client_id",
            client_secret: "client_secret",
            send_inactive_token_response: fn conn ->
              Plug.Conn.send_resp(conn, 500, "invalid")
            end
          )

        assert %{
                 status: 500,
                 private: %{ValidateJwtToken => nil},
                 resp_body: "invalid"
               } =
                 "get"
                 |> conn("/", "")
                 |> put_private(ExtractAuthorization, "token")
                 |> ValidateJwtToken.call(opts)
      end
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
        %{scope: ["urn:zitadel:iam:org:project:id:#{project_id}:aud", "profile"], kid: kid}
      )

    opts =
      ValidateJwtToken.init(
        provider: pid,
        client_id: project_id,
        client_secret: client_secret
      )

    assert %{halted: false, private: %{ValidateJwtToken => %{"sub" => ^subject}}} =
             "get"
             |> conn("/", "")
             |> put_private(ExtractAuthorization, access_token)
             |> ValidateJwtToken.call(opts)
  end
end
