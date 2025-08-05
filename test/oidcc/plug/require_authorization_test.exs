defmodule Oidcc.Plug.RequireAuthorizationTest do
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias Oidcc.Plug.ExtractAuthorization
  alias Oidcc.Plug.RequireAuthorization

  doctest RequireAuthorization

  describe inspect(&RequireAuthorization.call/2) do
    test "errors without ExtractAuthorization" do
      opts =
        RequireAuthorization.init([])

      assert_raise RuntimeError, fn ->
        "get"
        |> conn("/", "")
        |> RequireAuthorization.call(opts)
      end
    end

    test "send error response if no token provided" do
      opts =
        RequireAuthorization.init([])

      assert %{
               halted: true,
               status: 401,
               resp_headers: [
                 {"cache-control", "max-age=0, private, must-revalidate"},
                 {"www-authenticate", "Bearer"}
               ]
             } =
               "get"
               |> conn("/", "")
               |> put_private(ExtractAuthorization, nil)
               |> RequireAuthorization.call(opts)
    end

    test "pass if token provided" do
      opts =
        RequireAuthorization.init([])

      assert %{halted: false} =
               "get"
               |> conn("/", "")
               |> put_private(ExtractAuthorization, "some_access_token")
               |> RequireAuthorization.call(opts)
    end
  end
end
