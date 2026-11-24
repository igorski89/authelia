// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

import { render, screen } from "@testing-library/react";

import DecisionFormClient from "@views/ConsentPortal/OpenIDConnect/DecisionFormClient";

vi.mock("react-i18next", () => ({
    useTranslation: () => ({ t: (key: string) => key }),
}));

it("renders the client description as the name", () => {
    render(<DecisionFormClient client_id={"test-client"} client_description={"Test Client"} />);

    expect(screen.getByText("Test Client")).toBeInTheDocument();
});

it("renders the client id alongside the description", () => {
    render(<DecisionFormClient client_id={"test-client"} client_description={"Test Client"} />);

    expect(screen.getByText("test-client")).toBeInTheDocument();
});

it("renders the client id as the name when the description is empty", () => {
    render(<DecisionFormClient client_id={"test-client"} client_description={""} />);

    expect(screen.getByTestId("openid-consent-client-name")).toHaveTextContent("test-client");
});

it("does not repeat the client id when the description is empty", () => {
    render(<DecisionFormClient client_id={"test-client"} client_description={""} />);

    expect(screen.getAllByText("test-client")).toHaveLength(1);
});

it("says a client of a Client ID Metadata Document isn't pre-registered, and when it returns to the computer", () => {
    render(
        <DecisionFormClient
            client_id="https://claude.ai/client.json"
            client_description="claude.ai"
            metadata_document_host="claude.ai"
            loopback
        />,
    );

    expect(screen.getByTestId("openid-consent-client-metadata-document-host")).toHaveTextContent(
        "Not a pre-registered app, identified by {{host}}",
    );
    expect(screen.getByTestId("openid-consent-client-loopback")).toBeInTheDocument();
});

it("shows no note for a registered client", () => {
    render(<DecisionFormClient client_id="app" client_description="App" />);

    expect(screen.queryByTestId("openid-consent-client-metadata-document-host")).not.toBeInTheDocument();
    expect(screen.queryByTestId("openid-consent-client-loopback")).not.toBeInTheDocument();
});
