# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

Mimic.copy(:oidcc_jwt_util)
Mimic.copy(Oidcc)
Mimic.copy(Oidcc.Authorization)
Mimic.copy(Oidcc.ClientContext)
Mimic.copy(Oidcc.Token)
Mimic.copy(Oidcc.TokenIntrospection)
Mimic.copy(Oidcc.Userinfo)

ExUnit.start()
