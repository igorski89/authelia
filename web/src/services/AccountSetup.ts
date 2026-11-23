// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

import { AccountSetupPath, CompleteAccountSetupPath } from "@services/Api";
import { PostWithOptionalResponse } from "@services/Client";

// completeAccountSetupProcess redeems the one-time invite link token.
export async function completeAccountSetupProcess(token: string) {
    return PostWithOptionalResponse(CompleteAccountSetupPath, { token });
}

// setupAccount sets the password of the invited user, who is then logged in.
export async function setupAccount(password: string) {
    return PostWithOptionalResponse(AccountSetupPath, { password });
}
