// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"testing"
	"time"

	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/token/jwt"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/authelia/authelia/v4/internal/mocks"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/oidc"
)

func TestAuthzBearerRevoked(t *testing.T) {
	requested := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

	session := &oidc.Session{DefaultSession: &openid.DefaultSession{Claims: &jwt.IDTokenClaims{}, Username: "john", RequestedAt: requested}, ClientID: "app"}

	mock := mocks.NewMockAutheliaCtx(t)
	defer mock.Close()

	store := mocks.NewMockStorage(gomock.NewController(t))
	mock.Ctx.Providers.StorageProvider = store

	store.EXPECT().LoadUserRevocations(gomock.Any(), "john").Return([]model.UserRevocation{{Username: "john", ClientID: "app", RevokedAt: requested.Add(time.Millisecond)}}, nil)

	assert.EqualError(t, authzBearerRevoked(mock.Ctx, session), "the token was revoked since its grant was authorized")
	assert.NoError(t, authzBearerRevoked(context.Background(), session), "a context without the providers isn't checked")
}
