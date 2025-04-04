<div style="margin-right: 15px; float: left;">
  <img
    align="left"
    src="assets/logo.svg"
    alt="OpenID Connect Logo"
    width="170px"
  />
</div>

# Oidcc.Plug

Plug Integration for [`oidcc`](https://hex.pm/packages/oidcc) library.

[![EEF Security WG project](https://img.shields.io/badge/EEF-Security-black)](https://github.com/erlef/security-wg)
[![Main Branch](https://github.com/erlef/oidcc_plug/actions/workflows/branch_main.yml/badge.svg?branch=main)](https://github.com/erlef/oidcc_plug/actions/workflows/branch_main.yml)
[![Module Version](https://img.shields.io/hexpm/v/oidcc_plug.svg)](https://hex.pm/packages/oidcc_plug)
[![Total Download](https://img.shields.io/hexpm/dt/oidcc_plug.svg)](https://hex.pm/packages/oidcc_plug)
[![License](https://img.shields.io/hexpm/l/oidcc_plug.svg)](https://github.com/erlef/oidcc_plug/blob/main/LICENSE)
[![Last Updated](https://img.shields.io/github/last-commit/erlef/oidcc_plug.svg)](https://github.com/erlef/oidcc_plug/commits/master)
[![Coverage Status](https://coveralls.io/repos/github/erlef/oidcc_plug/badge.svg?branch=main)](https://coveralls.io/github/erlef/oidcc_plug?branch=main)

<br clear="left"/>

<picture style="margin-right: 15px; float: left;">
  <source
    media="(prefers-color-scheme: dark)"
    srcset="assets/certified-dark.svg"
    width="170px"
    align="left"
  />
  <source
    media="(prefers-color-scheme: light)"
    srcset="assets/certified-light.svg"
    width="170px"
    align="left"
  />
  <img
    src="assets/certified-light.svg"
    alt="OpenID Connect Certified Logo"
    width="170px"
    align="left"
  />
</picture>

OpenID Certified by [Jonatan Männchen](https://github.com/maennchen) at the
[Erlang Ecosystem Foundation](https://github.com/erlef) of multiple Relaying
Party conformance profiles of the OpenID Connect protocol:
For details, check the
[Conformance Test Suite](https://github.com/erlef/oidcc_conformance).

<br clear="left"/>

<picture style="margin-right: 15px; float: left;">
  <source
    media="(prefers-color-scheme: dark)"
    srcset="assets/erlef-logo-dark.svg"
    width="170px"
    align="left"
  />
  <source
    media="(prefers-color-scheme: light)"
    srcset="assets/erlef-logo-light.svg"
    width="170px"
    align="left"
  />
  <img
    src="assets/erlef-logo-light.svg"
    alt="Erlang Ecosystem Foundation Logo"
    width="170px"
    align="left"
  />
</picture>

The development of the library and the certification is funded as an
[Erlang Ecosystem Foundation](https://erlef.org/) stipend entered by the
[Security Working Group](https://erlef.org/wg/security).

<br clear="left"/>

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

You can use [`igniter`](https://hex.pm/packages/igniter) to generate a basic
setup for phoenix:

```bash
# If you haven't created your phoenix project yet
# See: https://hexdocs.pm/igniter/readme.html#creating-a-new-mix-project-using-igniter
mix igniter.new test \
  --install phoenix,oidcc,oidcc_plug \
  --with phx.new
  
# Add Igniter Phoenix Extension
mix igniter.add_extension phoenix

# Generate Provider, Controller, Router & Config
mix oidcc.gen.controller \
    --name MyApp.AuthController \
    --provider MyApp.OpenIDProvider \
    --base-url /auth \
    --issuer https://account.google.com \
    --client-id client-id
```

## Usage

### Setup

```elixir
defmodule SampleApp.Application do
  # ...

  @impl true
  def start(_type, _args) do
    children = [
      # ...

      {Oidcc.ProviderConfiguration.Worker, %{
        issuer: "https://accounts.google.com",
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
```

### Authorization Flow

```elixir
defmodule SampleAppWeb.OidccController do
  use SampleAppWeb, :controller

  plug Oidcc.Plug.Authorize,
    [
      provider: TestWorks.OpenIdConfigurationProvider,
      client_id: "client_id",
      client_secret: "client_secret",
      redirect_uri: &__MODULE__.callback_uri/0
    ]
    when action in [:authorize]

  plug Oidcc.Plug.AuthorizationCallback,
    [
      provider: TestWorks.OpenIdConfigurationProvider,
      client_id: "client_id",
      client_secret: "client_secret",
      redirect_uri: &__MODULE__.callback_uri/0
    ]
    when action in [:callback]

  @doc false
  def callback_uri, do: url(~p"/oidcc/callback")

  def authorize(conn, _params), do: conn

  def callback(%Plug.Conn{private: %{
    Oidcc.Plug.AuthorizationCallback => {:ok, {_token, userinfo}}}
  } = conn, params) do
    conn
    |> put_session("oidcc_claims", userinfo)
    |> redirect(to: "/")
  end

  def callback(%Plug.Conn{private: %{
    Oidcc.Plug.AuthorizationCallback => {:error, reason}
  }} = conn, _params) do
    conn
    |> put_status(400)
    |> render(:error, reason: reason)
  end
end
```

### API (Check access token header)

```elixir
defmodule SampleAppWeb.Endpoint do
  use Phoenix.Endpoint, otp_app: :sample_app

  # ...

  plug Oidcc.Plug.ExtractAuthorization

  @client_id Application.compile_env!(:sample_app, [:openid_credentials, :client_id])
  @client_secret Application.compile_env!(:sample_app, [:openid_credentials, :client_secret])

  # Ensure Authorization Token provided
  plug Oidcc.Plug.RequireAuthorization

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
