// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

import * as React from "react";

import { Body, Container, Head, Heading, Hr, Html, Preview, Section, Text, Tailwind, Button, Link } from "react-email";

import { Brand } from "../components/Brand";

interface Props {
    title?: string;
    displayName?: string;
    domain?: string;
    link?: string;
    linkText?: string;
    expires?: string;
    hidePreview?: boolean;
    isPlainText?: boolean;
}

export const AccountSetup = ({
    title,
    displayName,
    domain,
    link,
    linkText,
    expires,
    hidePreview,
    isPlainText,
}: Props) => {
    return (
        <Html lang="en" dir="ltr">
            <Tailwind>
                <Head />
                {hidePreview ? null : <Preview>{title || "Set up your account"}</Preview>}
                <Body className="bg-white my-auto mx-auto font-sans px-2">
                    <Container className="border border-solid border-[#eaeaea] rounded my-[40px] mx-auto p-[20px] max-w-[465px]">
                        <Heading className="text-black text-[24px] font-normal text-center p-0 my-[30px] mx-0">
                            You have been invited to <strong>set up your account</strong>
                        </Heading>
                        <Text className="text-black text-[14px] leading-[24px]">Hi {displayName},</Text>
                        <Text className="text-black text-[14px] leading-[24px]">
                            An administrator has created an account for you at <i>{domain}</i>. Use the{" "}
                            <strong>one-time link</strong> below to choose a password and register a passkey.
                        </Text>
                        <Text className="text-black text-[14px] leading-[24px] text-center">
                            <strong>
                                Do not share this notification or the content of this notification with anyone.
                            </strong>
                        </Text>
                        <Hr className="border border-solid border-[#eaeaea] my-[12px] mx-0 w-full" />
                        {isPlainText ? (
                            <>
                                <Text className="text-black text-[14px] leading-[24px] text-center">
                                    To set up your account, open the link below.
                                </Text>
                                <Text className="text-black text-[14px] leading-[24px] text-center">{link}</Text>
                            </>
                        ) : (
                            <>
                                <Section className="text-center">
                                    <Button
                                        id="link"
                                        href={link}
                                        className="bg-[#1976d2] rounded text-white text-[12px] font-semibold no-underline text-center px-5 py-3"
                                    >
                                        {linkText}
                                    </Button>
                                </Section>
                                <Text className="text-black text-[14px] leading-[24px] text-center">
                                    Alternatively, copy and paste this URL into your browser:
                                </Text>
                                <Section className="text-center">
                                    <Link
                                        href={link}
                                        className="text-blue-600 hover:text-blue-800 visited:text-purple-600 text-[12px] no-underline"
                                        style={{ wordBreak: "break-all" }}
                                    >
                                        {link}
                                    </Link>
                                </Section>
                            </>
                        )}
                        <Hr className="border border-solid border-[#eaeaea] my-[26px] mx-0 w-full" />
                        <Text className="text-[#666666] text-[12px] leading-[24px] text-center">
                            This link can be used once and expires at <span className="text-black">{expires}</span>.
                            If you were not expecting this invitation, you can ignore this email; ask an administrator
                            if you need a new link.
                        </Text>
                        <Text className="text-[#666666] text-[12px] leading-[24px] text-center">
                            This email was intended for <span className="text-black">{displayName}</span>.
                        </Text>
                    </Container>
                    <Brand />
                </Body>
            </Tailwind>
        </Html>
    );
};

AccountSetup.PreviewProps = {
    title: "Set up your account",
    displayName: "John Doe",
    domain: "example.com",
    link: "https://auth.example.com/account-setup?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20ifQ.signature",
    linkText: "Set up your account",
    expires: "2026-11-26 18:00:00 UTC",
    hidePreview: false,
    isPlainText: false,
} as Props;

export default AccountSetup;
