<img align="left" src="https://raw.githubusercontent.com/erlef/oidcc_plug/main/assets/logo.svg" width="150px" style="margin-right: 15px">

# Oidcc.Plug

[![EEF Security WG project](https://img.shields.io/badge/EEF-Security-black)](https://github.com/erlef/security-wg)
[![Main Branch](https://github.com/erlef/oidcc_plug/actions/workflows/branch_main.yml/badge.svg?branch=main)](https://github.com/erlef/oidcc_plug/actions/workflows/branch_main.yml)
[![Module Version](https://img.shields.io/hexpm/v/oidcc_plug.svg)](https://hex.pm/packages/oidcc_plug)
[![Total Download](https://img.shields.io/hexpm/dt/oidcc_plug.svg)](https://hex.pm/packages/oidcc_plug)
[![License](https://img.shields.io/hexpm/l/oidcc_plug.svg)](https://github.com/erlef/oidcc_plug/blob/main/LICENSE)
[![Last Updated](https://img.shields.io/github/last-commit/erlef/oidcc_plug.svg)](https://github.com/erlef/oidcc_plug/commits/master)
[![Coverage Status](https://coveralls.io/repos/github/erlef/oidcc_plug/badge.svg?branch=main)](https://coveralls.io/github/erlef/oidcc_plug?branch=main)

Plug Integration for [`oidcc`](https://hex.pm/packages/oidcc) library.

<!-- TODO: Uncomment after certification -->
<!--
OpenID Certified by Jonatan Männchen at the Erlang Ecosystem Foundation for the
basic and configuration profile of the OpenID Connect protocol. For details,
check the [Conformance Documentation](https://github.com/erlef/oidcc/tree/openid-foundation-certification).

![OpenID Connect Certified Logo](https://raw.githubusercontent.com/erlef/oidcc_plug/main/assets/certified.svg)
-->

<picture style="margin-right: 15px; float: left">
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/erlef/oidcc_plug/main/assets/erlef-logo-dark.svg" width="115px" align="left">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/erlef/oidcc_plug/main/assets/erlef-logo-light.svg" width="115px" align="left">
  <img alt="Erlang Ecosystem Foundation Logo" src="https://raw.githubusercontent.com/erlef/oidcc_plug/main/assets/erlef-logo-light.svg" width="115px" align="left">
</picture>

The development of the library and the certification is funded as an
[Erlang Ecosystem Foundation](https://erlef.org/) stipend entered by the
[Security Working Group](https://erlef.org/wg/security).

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

