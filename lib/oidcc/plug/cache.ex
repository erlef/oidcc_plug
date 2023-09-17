defmodule Oidcc.Plug.Cache do
  @moduledoc """
  Behaviour to cache introspection / userinfo requests

  ## Usage

  * Userinfo: See `t:Oidcc.Plug.LoadUserinfo.opts/0` / `cache`
  * Introspection: See `t:Oidcc.Plug.IntrospectToken.opts/0` / `cache`
  """
  @moduledoc since: "0.1.0"

  @type t() :: module()

  @doc """
  Check cache if userinfo / introspection is stored for `token`.
  """
  @doc since: "0.1.0"
  @callback get(type :: :userinfo, token :: String.t(), conn :: Plug.Conn.t()) ::
              {:ok, :oidcc_jwt_util.claims()} | :miss
  @callback get(type :: :introspection, token :: String.t(), conn :: Plug.Conn.t()) ::
              {:ok, Oidcc.TokenIntrospection.t()} | :miss

  @doc """
  Store userinfo / introspection for `token`.
  """
  @doc since: "0.1.0"
  @callback put(
              type :: :userinfo | :introspection,
              token :: String.t(),
              data :: Oidcc.TokenIntrospection.t() | :oidcc_jwt_util.claims(),
              conn :: Plug.Conn.t()
            ) :: :ok
end
