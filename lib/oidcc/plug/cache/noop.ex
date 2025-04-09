defmodule Oidcc.Plug.Cache.Noop do
  @moduledoc false

  @behaviour Oidcc.Plug.Cache

  alias Oidcc.Plug.Cache

  @impl Cache
  def get(_type, _token, _conn), do: :miss

  @impl Cache
  def put(_type, _token, _data, _conn), do: :ok
end
