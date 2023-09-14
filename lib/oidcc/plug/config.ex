defmodule Oidcc.Plug.Config do
  @moduledoc false

  @spec evaluate_config(config :: value | (-> value)) :: value when value: term()
  def evaluate_config(config)
  def evaluate_config(config) when is_function(config, 0), do: config.()
  def evaluate_config(config), do: config
end
