# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-FileCopyrightText: 2025 Matt Enlow
#
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.Plug.Cache.Noop do
  @moduledoc false

  @behaviour Oidcc.Plug.Cache

  alias Oidcc.Plug.Cache

  @impl Cache
  def get(_type, _token, _conn), do: :miss

  @impl Cache
  def put(_type, _token, _data, _conn), do: :ok
end
