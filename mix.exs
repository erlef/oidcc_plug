defmodule Oidcc.Plug.MixProject do
  use Mix.Project

  def project do
    [
      app: :oidcc_plug,
      version: "0.2.2",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "Oidcc Plug",
      source_url: "https://github.com/erlef/oidcc_plug",
      docs: &docs/0,
      description: """
      Plug Integration for the oidcc OpenID Connect Library
      """,
      package: package(),
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test,
        "coveralls.github": :test,
        "coveralls.multiple": :test
      ],
      dialyzer: [
        plt_add_apps: [:mix]
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :inets, :ssl]
    ]
  end

  defp package() do
    [
      maintainers: ["Jonatan Männchen"],
      files: [
        "lib",
        "LICENSE*",
        "mix.exs",
        "README*"
      ],
      licenses: ["Apache-2.0"],
      links: %{"Github" => "https://github.com/erlef/oidcc_plug"}
    ]
  end

  defp docs do
    {ref, 0} = System.cmd("git", ["rev-parse", "--verify", "--quiet", "HEAD"])

    [
      main: "readme",
      source_ref: ref,
      extras: ["README.md"],
      logo: "assets/logo.svg",
      assets: %{"assets" => "assets"}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:oidcc, "~> 3.5"},
      {:plug, "~> 1.14"},
      {:igniter, "~> 0.5.43", optional: true},
      {:phoenix, "~> 1.7", only: [:dev, :test]},
      {:ex_doc, "~> 0.29", only: :dev, runtime: false},
      {:excoveralls, "~> 0.18.1", only: :test, runtime: false},
      {:dialyxir, "~> 1.4", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: :dev, runtime: false},
      {:mock, "~> 0.3.8", only: :test},
      {:phx_new, "~> 1.7", only: :test}
    ]
  end
end
