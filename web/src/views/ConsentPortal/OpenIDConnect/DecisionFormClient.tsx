// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

import { AppWindow } from "lucide-react";
import { useTranslation } from "react-i18next";

export interface Props {
    client_id: string;
    client_description: string;
    metadata_document_host?: string;
    loopback?: boolean;
}

function DecisionFormClient({ client_description, client_id, loopback, metadata_document_host }: Props) {
    const { t: translate } = useTranslation(["consent"]);

    const named = client_description !== "";

    return (
        <div className="flex w-full items-center gap-3 text-left">
            <span className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground">
                <AppWindow className="size-5" />
            </span>
            <span className="min-w-0 flex-1">
                <span
                    id={"openid-consent-client-name"}
                    data-testid={"openid-consent-client-name"}
                    className="block truncate font-semibold"
                >
                    {named ? client_description : client_id}
                </span>
                {named ? (
                    <span
                        id={"openid-consent-client-id"}
                        className="block truncate font-mono text-xs text-muted-foreground"
                        title={translate("Client ID", { client_id }) || `Client ID: ${client_id}`}
                    >
                        {client_id}
                    </span>
                ) : null}
                {metadata_document_host ? (
                    <span
                        id={"openid-consent-client-metadata-document-host"}
                        data-testid={"openid-consent-client-metadata-document-host"}
                        className="block text-xs text-amber-700 dark:text-amber-400"
                    >
                        {translate("Not a pre-registered app, identified by {{host}}", {
                            host: metadata_document_host,
                        })}
                    </span>
                ) : null}
                {metadata_document_host && loopback ? (
                    <span
                        id={"openid-consent-client-loopback"}
                        data-testid={"openid-consent-client-loopback"}
                        className="block text-xs text-amber-700 dark:text-amber-400"
                    >
                        {translate("This app returns to your own computer")}
                    </span>
                ) : null}
            </span>
        </div>
    );
}

export default DecisionFormClient;
