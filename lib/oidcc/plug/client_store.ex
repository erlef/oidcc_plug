defmodule Oidcc.Plug.ClientStore do
  @callback get_client_context(conn :: Plug.Conn.t()) ::
              {:error, term()} | {:ok, Oidcc.ClientContext.t()}

  @callback refresh_jwks(context :: Oidcc.ClientContext.t()) ::
              {:ok, JOSE.JWK.t()} | {:error, term()}

  @optional_callbacks refresh_jwks: 1
end
