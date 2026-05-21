/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

package org.elasticsearch.action;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.ResolvedIndexExpression.LocalExpressions;
import org.elasticsearch.action.ResolvedIndexExpression.LocalIndexResolutionResult;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.test.ESTestCase;

import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.sameInstance;

public class ResolvedIndexExpressionsTests extends ESTestCase {

    public void testExcludeFromLocalExpressionsEmptyExclusionsIsNoOp() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions("logs", mutableSet("logs"), LocalIndexResolutionResult.SUCCESS, Set.of());

        builder.excludeFromLocalExpressions(Set.of());

        ResolvedIndexExpressions resolved = builder.build();
        assertThat(resolved.expressions(), hasSize(1));
        assertEntry(resolved.expressions().get(0), "logs", LocalIndexResolutionResult.SUCCESS, Set.of("logs"));
    }

    public void testExcludeFromLocalExpressionsRemovesMatchingIndicesFromSuccess() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions("logs*", mutableSet("logs-1", "logs-2"), LocalIndexResolutionResult.SUCCESS, Set.of());

        builder.excludeFromLocalExpressions(Set.of("logs-1"));

        ResolvedIndexExpressions resolved = builder.build();
        assertThat(resolved.expressions(), hasSize(1));
        assertEntry(resolved.expressions().get(0), "logs*", LocalIndexResolutionResult.SUCCESS, Set.of("logs-2"));
    }

    public void testExcludeFromLocalExpressionsEmptiesSuccessIndicesButKeepsEntry() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions("logs", mutableSet("logs"), LocalIndexResolutionResult.SUCCESS, Set.of());

        builder.excludeFromLocalExpressions(Set.of("logs"));

        ResolvedIndexExpressions resolved = builder.build();
        assertThat(resolved.expressions(), hasSize(1));
        assertEntry(resolved.expressions().get(0), "logs", LocalIndexResolutionResult.SUCCESS, Set.of());
    }

    public void testExcludeFromLocalExpressionsKeepsConcreteResourceNotVisibleWithEmptyIndices() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions("logs", mutableSet("logs"), LocalIndexResolutionResult.CONCRETE_RESOURCE_NOT_VISIBLE, Set.of());

        builder.excludeFromLocalExpressions(Set.of("logs"));

        ResolvedIndexExpressions resolved = builder.build();
        assertThat(resolved.expressions(), hasSize(1));
        assertEntry(resolved.expressions().get(0), "logs", LocalIndexResolutionResult.CONCRETE_RESOURCE_NOT_VISIBLE, Set.of());
    }

    public void testExcludeFromLocalExpressionsKeepsConcreteResourceUnauthorizedWithExceptionAndEmptyIndices() {
        var builder = ResolvedIndexExpressions.builder();
        var unauthorized = new ElasticsearchSecurityException("denied", RestStatus.FORBIDDEN);
        builder.addExpression(
            new ResolvedIndexExpression(
                "logs",
                new LocalExpressions(mutableSet("logs"), LocalIndexResolutionResult.CONCRETE_RESOURCE_UNAUTHORIZED, unauthorized),
                Set.of()
            )
        );

        builder.excludeFromLocalExpressions(Set.of("logs"));

        ResolvedIndexExpressions resolved = builder.build();
        assertThat(resolved.expressions(), hasSize(1));
        var entry = resolved.expressions().get(0);
        assertThat(entry.original(), equalTo("logs"));
        assertThat(entry.localExpressions().indices(), empty());
        assertThat(entry.localExpressions().localIndexResolutionResult(), is(LocalIndexResolutionResult.CONCRETE_RESOURCE_UNAUTHORIZED));
        assertThat(entry.localExpressions().exception(), notNullValue());
        assertThat(entry.localExpressions().exception(), sameInstance(unauthorized));
    }

    public void testExcludeFromLocalExpressionsLeavesUnrelatedEntriesUntouched() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions("logs", mutableSet("logs"), LocalIndexResolutionResult.SUCCESS, Set.of());
        builder.addExpressions("metrics", mutableSet("metrics"), LocalIndexResolutionResult.SUCCESS, Set.of());

        builder.excludeFromLocalExpressions(Set.of("logs"));

        ResolvedIndexExpressions resolved = builder.build();
        assertThat(resolved.expressions(), hasSize(2));
        assertEntry(resolved.expressions().get(0), "logs", LocalIndexResolutionResult.SUCCESS, Set.of());
        assertEntry(resolved.expressions().get(1), "metrics", LocalIndexResolutionResult.SUCCESS, Set.of("metrics"));
    }

    public void testExcludeFromLocalExpressionsAppliesAcrossMultipleEntries() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions("logs*", mutableSet("logs-1", "logs-2"), LocalIndexResolutionResult.SUCCESS, Set.of());
        builder.addExpressions("logs-1", mutableSet("logs-1"), LocalIndexResolutionResult.SUCCESS, Set.of());

        builder.excludeFromLocalExpressions(Set.of("logs-1"));

        ResolvedIndexExpressions resolved = builder.build();
        assertThat(resolved.expressions(), hasSize(2));
        assertThat(resolved.expressions().get(0).original(), equalTo("logs*"));
        assertThat(resolved.expressions().get(0).localExpressions().indices(), containsInAnyOrder("logs-2"));
        assertThat(resolved.expressions().get(1).original(), equalTo("logs-1"));
        assertThat(resolved.expressions().get(1).localExpressions().indices(), empty());
    }

    public void testExcludeFromLocalExpressionsSkipsEntriesWithEmptyIndices() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addRemoteExpressions("remote:logs", Set.of("remote:logs"));

        builder.excludeFromLocalExpressions(Set.of("logs"));

        ResolvedIndexExpressions resolved = builder.build();
        assertThat(resolved.expressions(), hasSize(1));
        assertThat(resolved.expressions().get(0).original(), equalTo("remote:logs"));
        assertThat(resolved.expressions().get(0).localExpressions(), sameInstance(LocalExpressions.NONE));
        assertThat(resolved.expressions().get(0).remoteExpressions(), contains("remote:logs"));
    }

    private static void assertEntry(
        ResolvedIndexExpression entry,
        String original,
        LocalIndexResolutionResult result,
        Set<String> indices
    ) {
        assertThat(entry.original(), equalTo(original));
        assertThat(entry.localExpressions().localIndexResolutionResult(), is(result));
        assertThat(entry.localExpressions().indices(), equalTo(indices));
    }

    private static HashSet<String> mutableSet(String... values) {
        HashSet<String> set = new HashSet<>();
        for (String value : values) {
            set.add(value);
        }
        return set;
    }
}
