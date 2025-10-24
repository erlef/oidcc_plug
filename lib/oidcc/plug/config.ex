defmodule Oidcc.Plug.Config do
  @moduledoc false

  @spec evaluate_config(config :: value | (-> value) | (Plug.Conn.t() -> value), Plug.Conn.t()) :: value
        when value: term()
  def evaluate_config(config, conn)
  def evaluate_config(config, _conn) when is_function(config, 0), do: config.()
  def evaluate_config(config, conn) when is_function(config, 1), do: config.(conn)

  def evaluate_config(config, _conn) when is_function(config),
    do: raise(ArgumentError, "Config function must have arity 0 or 1")

  def evaluate_config(config, _conn), do: config
end
