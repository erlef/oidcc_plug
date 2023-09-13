defmodule Oidcc.Plug.Cache.Noop do
  @moduledoc false

  alias Oidcc.Plug.Cache

  @behaviour Cache

  @impl Cache
  def get(_type, _token, _conn), do: :miss

  @impl Cache
  def put(_type, _token, _data, _conn), do: :ok
end
