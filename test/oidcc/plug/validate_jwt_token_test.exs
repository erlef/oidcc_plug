defmodule Oidcc.Plug.ValidateJwtTokenTest do
  use ExUnit.Case, async: false
  use Mimic

  import Plug.Conn
  import Plug.Test

  alias Oidcc.Plug.ClientStore
  alias Oidcc.Plug.ExtractAuthorization
  alias Oidcc.Plug.ValidateJwtToken

  doctest ValidateJwtToken

  describe inspect(&ValidateJwtToken.call/2) do
    test "validates token using jwt" do
      stub(Oidcc.ClientContext, :from_configuration_worker, fn ProviderName, "client_id", "client_secret", %{} ->
        {:ok, :client_context}
      end)

      stub(Oidcc.Token, :validate_id_token, fn "token", :client_context, %{nonce: :any, refresh_jwks: _} ->
        {:ok, %{"sub" => "sub"}}
      end)

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
      stub(Oidcc.ClientContext, :from_configuration_worker, fn ProviderName, "client_id", "client_secret", %{} ->
        {:ok, :client_context}
      end)

      stub(Oidcc.Token, :validate_id_token, fn "token", :client_context, %{nonce: :any, refresh_jwks: _} ->
        {:error, :reason}
      end)

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

    test "sends error response with inactive token" do
      stub(Oidcc.ClientContext, :from_configuration_worker, fn ProviderName, "client_id", "client_secret", %{} ->
        {:ok, :client_context}
      end)

      stub(Oidcc.Token, :validate_id_token, fn "token", :client_context, %{nonce: :any, refresh_jwks: _} ->
        {:error, :token_expired}
      end)

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

    test "can customize inactive token response" do
      stub(Oidcc.ClientContext, :from_configuration_worker, fn ProviderName, "client_id", "client_secret", %{} ->
        {:ok, :client_context}
      end)

      stub(Oidcc.Token, :validate_id_token, fn "token", :client_context, %{nonce: :any, refresh_jwks: _} ->
        {:error, :token_expired}
      end)

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

  describe "client_store" do
    defmodule TestClientStore do
      @moduledoc false
      @behaviour ClientStore

      @impl ClientStore
      def get_client_context(_conn), do: {:ok, :client_context_from_store}

      @impl ClientStore
      def refresh_jwks(context), do: {:ok, {:refreshed_by_store, context}}
    end

    defmodule ErrorClientStore do
      @moduledoc false
      @behaviour ClientStore

      @impl ClientStore
      def get_client_context(_conn), do: {:error, :client_context_not_found}
    end

    defmodule RotatingClientStore do
      @moduledoc false
      @behaviour ClientStore

      @impl ClientStore
      def get_client_context(conn), do: {:ok, conn.private.client_context}

      @impl ClientStore
      def refresh_jwks(_context), do: {:ok, :persistent_term.get({Oidcc.Plug.ValidateJwtTokenTest, :rotated_jwks})}
    end

    defp public_jwk(key, kid) do
      {_type, map} = key |> JOSE.JWK.to_public() |> JOSE.JWK.to_map()

      JOSE.JWK.from_map(Map.merge(map, %{"use" => "sig", "kid" => kid}))
    end

    test "init accepts client_store" do
      opts = ValidateJwtToken.init(client_store: TestClientStore)

      assert Keyword.fetch!(opts, :client_store) == TestClientStore
    end

    test "init rejects client_store mixed with provider options" do
      assert_raise ArgumentError, ~r/Invalid options:.*/, fn ->
        ValidateJwtToken.init(client_store: TestClientStore, provider: ProviderName)
      end
    end

    test "validates token using the client context from the store" do
      test_pid = self()

      stub(Oidcc.Token, :validate_id_token, fn "token", client_context, %{nonce: :any, refresh_jwks: refresh_jwks} ->
        send(test_pid, {:validated_with, client_context, refresh_jwks})
        {:ok, %{"sub" => "sub"}}
      end)

      opts = ValidateJwtToken.init(client_store: TestClientStore)

      assert %{halted: false, private: %{ValidateJwtToken => %{"sub" => "sub"}}} =
               "get"
               |> conn("/", "")
               |> put_private(ExtractAuthorization, "token")
               |> ValidateJwtToken.call(opts)

      assert_received {:validated_with, :client_context_from_store, refresh_jwks}

      # oidcc calls the refresh fun with (jwks, kid), and it must reach the
      # store with the client context
      assert refresh_jwks.(:stale_jwks, "unknown_kid") ==
               {:ok, {:refreshed_by_store, :client_context_from_store}}
    end

    test "relays a client_store error" do
      opts = ValidateJwtToken.init(client_store: ErrorClientStore)

      assert_raise ValidateJwtToken.Error, fn ->
        "get"
        |> conn("/", "")
        |> put_private(ExtractAuthorization, "token")
        |> ValidateJwtToken.call(opts)
      end
    end

    test "validates a token signed with a rotated key by refreshing the jwks" do
      # the context only knows kid "a", the token is signed with kid "b" => the
      # store has to supply the rotated key for validation to succeed
      old_key = JOSE.JWK.generate_key({:rsa, 2048})
      new_key = JOSE.JWK.generate_key({:rsa, 2048})

      :persistent_term.put({__MODULE__, :rotated_jwks}, public_jwk(new_key, "b"))

      {:ok, provider_configuration} =
        Oidcc.ProviderConfiguration.decode_configuration(%{
          "issuer" => "https://example.com",
          "authorization_endpoint" => "https://example.com/auth",
          "jwks_uri" => "https://example.com/jwks",
          "scopes_supported" => ["openid"],
          "response_types_supported" => ["code"],
          "subject_types_supported" => ["public"],
          "id_token_signing_alg_values_supported" => ["RS256"]
        })

      client_context =
        Oidcc.ClientContext.from_manual(
          provider_configuration,
          public_jwk(old_key, "a"),
          "client_id",
          "client_secret",
          %{}
        )

      now = System.system_time(:second)

      {_, token} =
        new_key
        |> JOSE.JWT.sign(%{"alg" => "RS256", "kid" => "b"}, %{
          "iss" => "https://example.com",
          "sub" => "sub",
          "aud" => "client_id",
          "exp" => now + 3600,
          "iat" => now - 10
        })
        |> JOSE.JWS.compact()

      opts = ValidateJwtToken.init(client_store: RotatingClientStore)

      assert %{halted: false, private: %{ValidateJwtToken => %{"sub" => "sub"}}} =
               "get"
               |> conn("/", "")
               |> put_private(:client_context, client_context)
               |> put_private(ExtractAuthorization, token)
               |> ValidateJwtToken.call(opts)
    end
  end

  test "integration test" do
    pid =
      start_link_supervised!({Oidcc.ProviderConfiguration.Worker, %{issuer: "https://erlef-test-w4a8z2.zitadel.cloud"}})

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
