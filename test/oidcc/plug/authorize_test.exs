defmodule Oidcc.Plug.AuthorizeTest do
  use ExUnit.Case, async: false
  use Plug.Test

  import Mock

  alias Oidcc.Plug.Authorize

  doctest Authorize

  describe inspect(&Authorize.call/2) do
    test_with_mock "successful redirect", %{}, Oidcc, [],
      create_redirect_url: fn ProviderName,
                              "client_id",
                              "client_secret",
                              %{redirect_uri: "http://localhost:8080/oidc/return", nonce: _nonce} ->
        {:ok, "http://example.com"}
      end do
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

    test_with_mock "error handling", %{}, Oidcc, [],
      create_redirect_url: fn ProviderName,
                              "client_id",
                              "client_secret",
                              %{redirect_uri: "http://localhost:8080/oidc/return", nonce: _nonce} ->
        {:error, :provider_not_ready}
      end do
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
end
