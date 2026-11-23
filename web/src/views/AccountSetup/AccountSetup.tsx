// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

import { useTranslation } from "react-i18next";

import { SettingsRoute, SettingsTwoFactorAuthenticationSubRoute } from "@constants/Routes";
import { completeAccountSetupProcess, setupAccount } from "@services/AccountSetup";
import ResetPasswordStep2 from "@views/ResetPassword/ResetPasswordStep2";

// AccountSetup is where an invite link leads: the invited user chooses a password, is logged in, and goes on to
// register a passkey.
const AccountSetup = function () {
    const { t: translate } = useTranslation();

    return (
        <ResetPasswordStep2
            complete={completeAccountSetupProcess}
            submit={setupAccount}
            title={translate("Set up your account")}
            buttonText={translate("Continue")}
            successText={translate("Your password is set, now register a passkey")}
            successRoute={SettingsRoute + SettingsTwoFactorAuthenticationSubRoute}
        />
    );
};

export default AccountSetup;
