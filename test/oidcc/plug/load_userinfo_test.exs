# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-FileCopyrightText: 2025 Enzo Baldisserri
# SPDX-FileCopyrightText: 2025 Matt Enlow
#
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.Plug.LoadUserinfoTest do
  use ExUnit.Case, async: false
  use Mimic

  import Plug.Conn
  import Plug.Test

  alias Oidcc.Plug.ExtractAuthorization
  alias Oidcc.Plug.LoadUserinfo

  doctest LoadUserinfo

  describe inspect(&LoadUserinfo.call/2) do
    test "validates token using userinfo" do
      stub(Oidcc, :retrieve_userinfo, fn "token", ProviderName, "client_id", "client_secret", %{} ->
        {:ok, %{"sub" => "sub"}}
      end)

      opts =
        LoadUserinfo.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret"
        )

      assert %{
               halted: false,
               private: %{LoadUserinfo => %{"sub" => "sub"}}
             } =
               "get"
               |> conn("/", "")
               |> put_private(ExtractAuthorization, "token")
               |> LoadUserinfo.call(opts)
    end

    test "errors without ExtractAuthorization" do
      opts =
        LoadUserinfo.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret"
        )

      assert_raise RuntimeError, fn ->
        "get"
        |> conn("/", "")
        |> LoadUserinfo.call(opts)
      end
    end

    test "skips without token" do
      opts =
        LoadUserinfo.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret"
        )

      assert %{halted: false} =
               "get"
               |> conn("/", "")
               |> put_private(ExtractAuthorization, nil)
               |> LoadUserinfo.call(opts)
    end

    test "relays userinfo error" do
      stub(Oidcc, :retrieve_userinfo, fn "token", ProviderName, "client_id", "client_secret", %{} ->
        {:error, :reason}
      end)

      opts =
        LoadUserinfo.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret"
        )

      assert_raise LoadUserinfo.Error, fn ->
        "get"
        |> conn("/", "")
        |> put_private(ExtractAuthorization, "token")
        |> LoadUserinfo.call(opts)
      end
    end

    test "sends error response with inactive token" do
      stub(Oidcc, :retrieve_userinfo, fn "token", ProviderName, "client_id", "client_secret", %{} ->
        {:error, {:http_error, 401, "invalid_token"}}
      end)

      opts =
        LoadUserinfo.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret"
        )

      assert %{
               halted: true,
               status: 401,
               resp_body: "The provided token is inactive"
             } =
               "get"
               |> conn("/", "")
               |> put_private(ExtractAuthorization, "token")
               |> LoadUserinfo.call(opts)
    end

    test "can customize inactive token response" do
      stub(Oidcc, :retrieve_userinfo, fn "token", ProviderName, "client_id", "client_secret", %{} ->
        {:error, {:http_error, 401, "invalid_token"}}
      end)

      opts =
        LoadUserinfo.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret",
          send_inactive_token_response: fn conn ->
            Plug.Conn.send_resp(conn, 500, "invalid")
          end
        )

      assert %{
               status: 500,
               resp_body: "invalid"
             } =
               "get"
               |> conn("/", "")
               |> put_private(ExtractAuthorization, "token")
               |> LoadUserinfo.call(opts)
    end

    test "uses cache if provided and found" do
      defmodule Cache do
        @moduledoc false
        @behaviour Oidcc.Plug.Cache

        alias Oidcc.Plug.Cache

        @impl Cache
        def get(_type, _token, _conn), do: {:ok, %{"sub" => "sub"}}

        @impl Cache
        def put(_type, _token, _data, _conn), do: :ok
      end

      opts =
        LoadUserinfo.init(
          provider: ProviderName,
          client_id: "client_id",
          client_secret: "client_secret",
          cache: Cache
        )

      assert %{
               halted: false,
               private: %{LoadUserinfo => %{"sub" => "sub"}}
             } =
               "get"
               |> conn("/", "")
               |> put_private(ExtractAuthorization, "token")
               |> LoadUserinfo.call(opts)
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
      LoadUserinfo.init(
        provider: pid,
        client_id: client_id,
        client_secret: client_secret
      )

    assert %{halted: false, private: %{LoadUserinfo => %{"name" => "JWT Profile Test"}}} =
             "get"
             |> conn("/", "")
             |> put_private(ExtractAuthorization, access_token)
             |> LoadUserinfo.call(opts)
  end
end
