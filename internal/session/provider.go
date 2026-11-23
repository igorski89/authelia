// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"errors"
	"fmt"

	"github.com/authelia/authelia/v4/internal/clock"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/random"
)

// NewProvider returns a new Provider with a Strategy for every configured session cookie domain, each sharing the
// Codec derived from the session secret and HMAC key.
func NewProvider(config *schema.Configuration, hmac []byte, clock clock.Provider, random random.Provider, repository Repository) (provider Provider, err error) {
	var (
		codec Codec
	)

	if codec, err = NewCodec(config.Session.Secret, hmac, random); err != nil {
		return nil, err
	}

	strategies := make(map[string]Strategy, len(config.Session.Cookies))

	for _, cookie := range config.Session.Cookies {
		strategies[cookie.Domain] = NewStrategy(cookie, clock, codec, repository)
	}

	return &DefaultProvider{strategies: strategies, repository: repository}, nil
}

// DefaultProvider is the default Provider which resolves a Strategy from the cookie domain of a request.
type DefaultProvider struct {
	strategies map[string]Strategy
	repository Repository
}

// CountByUsername implements the Provider interface.
func (d DefaultProvider) CountByUsername(ctx context.Context, username string) (count int, err error) {
	for domain, strategy := range d.strategies {
		var (
			issuer string
			ids    []string
		)

		if issuer, err = issuerOf(domain, strategy); err != nil {
			return count, err
		}

		if ids, err = d.repository.GetIDsByUsername(ctx, issuer, username); err != nil {
			return count, fmt.Errorf("error listing the sessions of user '%s' on cookie domain '%s': %w", username, domain, err)
		}

		count += len(ids)
	}

	return count, nil
}

// DestroyByUsername implements the Provider interface.
func (d DefaultProvider) DestroyByUsername(ctx context.Context, username string) (destroyed int, err error) {
	for domain, strategy := range d.strategies {
		var (
			issuer string
			ids    []string
		)

		if issuer, err = issuerOf(domain, strategy); err != nil {
			return destroyed, err
		}

		if ids, err = d.repository.GetIDsByUsername(ctx, issuer, username); err != nil {
			return destroyed, fmt.Errorf("error listing the sessions of user '%s' on cookie domain '%s': %w", username, domain, err)
		}

		for _, id := range ids {
			// The backends retire the public identifier index they recorded when none is given.
			if err = d.repository.Delete(ctx, issuer, id, "", username); err != nil {
				return destroyed, fmt.Errorf("error destroying a session of user '%s' on cookie domain '%s': %w", username, domain, err)
			}

			destroyed++
		}
	}

	return destroyed, nil
}

// issuerOf returns the issuer the strategy stores its sessions under in the repository.
func issuerOf(domain string, strategy Strategy) (issuer string, err error) {
	if s, ok := strategy.(*DefaultStrategy); ok && s.issuer != "" {
		return s.issuer, nil
	}

	return "", fmt.Errorf("error resolving the session issuer of cookie domain '%s': unsupported strategy %T", domain, strategy)
}

// StartupCheck implements the Provider interface.
func (d DefaultProvider) StartupCheck() (err error) {
	return nil
}

// GetStrategy returns the Strategy configured for the given cookie domain, returning an error when the domain has no
// configured session cookie.
func (d DefaultProvider) GetStrategy(domain string) (strategy Strategy, err error) {
	var ok bool

	if strategy, ok = d.strategies[domain]; ok {
		return strategy, nil
	}

	return nil, errors.New("not found")
}

var (
	_ Provider = (*DefaultProvider)(nil)
)
