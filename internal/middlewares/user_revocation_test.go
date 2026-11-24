// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package middlewares_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
	"go.uber.org/mock/gomock"

	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/mocks"
	"github.com/authelia/authelia/v4/internal/model"
)

func TestIsUserRevokedLoadsMarksOncePerRequest(t *testing.T) {
	store := mocks.NewMockStorage(gomock.NewController(t))
	at := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

	store.EXPECT().LoadUserRevocations(gomock.Any(), "john").Return([]model.UserRevocation{{Username: "john", RevokedAt: at}}, nil).Times(1)

	ctx := &fasthttp.RequestCtx{}

	revoked, err := middlewares.IsUserRevoked(ctx, store, "john", "", at.Add(-time.Minute))
	require.NoError(t, err)
	assert.True(t, revoked)

	revoked, err = middlewares.IsUserRevoked(ctx, store, "john", "app", at.Add(time.Minute))
	require.NoError(t, err)
	assert.False(t, revoked)

	revoked, err = middlewares.IsUserRevoked(ctx, store, "", "", at)
	require.NoError(t, err)
	assert.False(t, revoked, "an anonymous session has no user to revoke")
}
