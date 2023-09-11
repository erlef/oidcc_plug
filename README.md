# Oidcc.Plug

[![Main Branch](https://github.com/Erlang-Openid/oidcc_plug/actions/workflows/branch_main.yml/badge.svg?branch=main)](https://github.com/Erlang-Openid/oidcc_plug/actions/workflows/branch_main.yml)
[![Module Version](https://img.shields.io/hexpm/v/oidcc_plug.svg)](https://hex.pm/packages/oidcc_plug)
[![Total Download](https://img.shields.io/hexpm/dt/oidcc_plug.svg)](https://hex.pm/packages/oidcc_plug)
[![License](https://img.shields.io/hexpm/l/oidcc_plug.svg)](https://github.com/Erlang-OpenID/oidcc_plug/blob/main/LICENSE)
[![Last Updated](https://img.shields.io/github/last-commit/Erlang-OpenID/oidcc_plug.svg)](https://github.com/Erlang-OpenID/oidcc_plug/commits/master)
[![Coverage Status](https://coveralls.io/repos/github/Erlang-Openid/oidcc_plug/badge.svg?branch=main)](https://coveralls.io/github/Erlang-Openid/oidcc_plug?branch=main)

Plug Integration for [`oidcc`](https://hex.pm/packages/oidcc) library.

## Installation

The package can be installed by adding `oidcc_plug` to your list of dependencies
in `mix.exs`:

```elixir
def deps do
  [
    {:oidcc_plug, "~> 0.1.0"}
  ]
end
```

## Usage

```elixir
defmodule SampleApp.Application do
  # ...

  @impl true
  def start(_type, _args) do
    children = [
      # ...

      {Oidcc.ProviderConfiguration.Worker, %{
        issuer: "https://accounts.google.com/",
        name: SampleApp.GoogleOpenIdConfigurationProvider
      }},

      # Start the Endpoint (http/https)
      SampleAppWeb.Endpoint
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: SampleApp.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # ...
end

defmodule SampleAppWeb.Endpoint do
  use Phoenix.Endpoint, otp_app: :sample_app

  # ...

  plug Oidcc.Plug.ExtractAuthorization

  @client_id Application.compile_env!(:sample_app, [:openid_credentials, :client_id])
  @client_secret Application.compile_env!(:sample_app, [:openid_credentials, :client_secret])

  # Check Token via Introspection
  plug Oidcc.Plug.IntrospectToken,
    provider: SampleApp.GoogleOpenIdConfigurationProvider,
    client_id: @client_id,
    client_secret: @client_secret

  # OR: Check Token via Userinfo
  plug Oidcc.Plug.LoadUserinfo,
    provider: SampleApp.GoogleOpenIdConfigurationProvider,
    client_id: @client_id,
    client_secret: @client_secret

  # OR: Check Token via JWT validation
  plug Oidcc.Plug.ValidateJwtToken,
    provider: SampleApp.GoogleOpenIdConfigurationProvider,
    client_id: @client_id,
    client_secret: @client_secret

  plug SampleAppWeb.Router
end
```

