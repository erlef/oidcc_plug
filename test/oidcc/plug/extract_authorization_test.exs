defmodule Oidcc.Plug.ExtractAuthorizationTest do
  use ExUnit.Case, async: true

  import Plug.Test
  import Plug.Conn

  alias Oidcc.Plug.ExtractAuthorization

  doctest ExtractAuthorization

  describe inspect(&ExtractAuthorization.call/2) do
    test "extracts bearer authorization header" do
      opts = ExtractAuthorization.init([])

      assert %{halted: false, private: %{ExtractAuthorization => "foo"}} =
               "get"
               |> conn("/", "")
               |> put_req_header("authorization", "Bearer foo")
               |> ExtractAuthorization.call(opts)
    end

    test "ignores missing header" do
      opts = ExtractAuthorization.init([])

      assert %{halted: false, private: %{ExtractAuthorization => nil}} =
               "get"
               |> conn("/", "")
               |> ExtractAuthorization.call(opts)
    end

    test "errors on malformatted header" do
      opts = ExtractAuthorization.init([])

      assert %{
               halted: true,
               resp_body: """
               Invalid authorization Header

               Expected: Authorization: Bearer <token>
               Given: \"invalid\"
               """,
               status: 400
             } =
               "get"
               |> conn("/", "")
               |> put_req_header("authorization", "invalid")
               |> ExtractAuthorization.call(opts)
    end

    test "can override error" do
      opts =
        ExtractAuthorization.init(
          send_invalid_header_response: fn conn, _headers ->
            Plug.Conn.send_resp(conn, 500, "invalid")
          end
        )

      assert %{resp_body: "invalid", status: 500} =
               "get"
               |> conn("/", "")
               |> put_req_header("authorization", "invalid")
               |> ExtractAuthorization.call(opts)
    end
  end
end
