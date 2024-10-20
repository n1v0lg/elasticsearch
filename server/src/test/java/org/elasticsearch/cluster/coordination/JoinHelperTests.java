/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */
package org.elasticsearch.cluster.coordination;

import org.apache.logging.log4j.Level;
import org.elasticsearch.Build;
import org.elasticsearch.Version;
import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.cluster.NotMasterException;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.DeterministicTaskQueue;
import org.elasticsearch.core.TimeValue;
import org.elasticsearch.monitor.StatusInfo;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.test.transport.CapturingTransport;
import org.elasticsearch.test.transport.CapturingTransport.CapturedRequest;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.ClusterConnectionManager;
import org.elasticsearch.transport.RemoteTransportException;
import org.elasticsearch.transport.TransportException;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.transport.TransportResponse;
import org.elasticsearch.transport.TransportService;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.elasticsearch.cluster.coordination.JoinHelper.PENDING_JOIN_WAITING_RESPONSE;
import static org.elasticsearch.monitor.StatusInfo.Status.HEALTHY;
import static org.elasticsearch.monitor.StatusInfo.Status.UNHEALTHY;
import static org.elasticsearch.transport.TransportService.HANDSHAKE_ACTION_NAME;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.core.Is.is;

public class JoinHelperTests extends ESTestCase {

    public void testJoinDeduplication() {
        DeterministicTaskQueue deterministicTaskQueue = new DeterministicTaskQueue();
        CapturingTransport capturingTransport = new HandshakingCapturingTransport();
        DiscoveryNode localNode = new DiscoveryNode("node0", buildNewFakeTransportAddress(), Version.CURRENT);
        final ThreadPool threadPool = deterministicTaskQueue.getThreadPool();
        TransportService transportService = new TransportService(
            Settings.EMPTY,
            capturingTransport,
            threadPool,
            TransportService.NOOP_TRANSPORT_INTERCEPTOR,
            x -> localNode,
            null,
            Collections.emptySet(),
            new ClusterConnectionManager(Settings.EMPTY, capturingTransport, threadPool.getThreadContext())
        );
        JoinHelper joinHelper = new JoinHelper(
            null,
            null,
            transportService,
            () -> 0L,
            (joinRequest, joinCallback) -> { throw new AssertionError(); },
            startJoinRequest -> { throw new AssertionError(); },
            (s, p, r) -> {},
            () -> new StatusInfo(HEALTHY, "info"),
            new JoinReasonService(() -> 0L)
        );
        transportService.start();

        DiscoveryNode node1 = new DiscoveryNode("node1", buildNewFakeTransportAddress(), Version.CURRENT);
        DiscoveryNode node2 = new DiscoveryNode("node2", buildNewFakeTransportAddress(), Version.CURRENT);
        final boolean mightSucceed = randomBoolean();

        assertFalse(joinHelper.isJoinPending());

        // check that sending a join to node1 works
        Optional<Join> optionalJoin1 = randomBoolean()
            ? Optional.empty()
            : Optional.of(new Join(localNode, node1, randomNonNegativeLong(), randomNonNegativeLong(), randomNonNegativeLong()));
        joinHelper.sendJoinRequest(node1, 0L, optionalJoin1);
        CapturedRequest[] capturedRequests1 = capturingTransport.getCapturedRequestsAndClear();
        assertThat(capturedRequests1.length, equalTo(1));
        CapturedRequest capturedRequest1 = capturedRequests1[0];
        assertEquals(node1, capturedRequest1.node());

        assertTrue(joinHelper.isJoinPending());
        final var join1Term = optionalJoin1.stream().mapToLong(Join::getTerm).findFirst().orElse(0L);
        final var join1Status = new JoinStatus(node1, join1Term, PENDING_JOIN_WAITING_RESPONSE, TimeValue.ZERO);
        assertThat(joinHelper.getInFlightJoinStatuses(), equalTo(List.of(join1Status)));

        // check that sending a join to node2 works
        Optional<Join> optionalJoin2 = randomBoolean()
            ? Optional.empty()
            : Optional.of(new Join(localNode, node2, randomNonNegativeLong(), randomNonNegativeLong(), randomNonNegativeLong()));
        joinHelper.sendJoinRequest(node2, 0L, optionalJoin2);
        CapturedRequest[] capturedRequests2 = capturingTransport.getCapturedRequestsAndClear();
        assertThat(capturedRequests2.length, equalTo(1));
        CapturedRequest capturedRequest2 = capturedRequests2[0];
        assertEquals(node2, capturedRequest2.node());

        final var join2Term = optionalJoin2.stream().mapToLong(Join::getTerm).findFirst().orElse(0L);
        final var join2Status = new JoinStatus(node2, join2Term, PENDING_JOIN_WAITING_RESPONSE, TimeValue.ZERO);
        assertThat(
            new HashSet<>(joinHelper.getInFlightJoinStatuses()),
            equalTo(
                Stream.of(join1Status, join2Status)
                    .filter(joinStatus -> joinStatus.term() == Math.max(join1Term, join2Term))
                    .collect(Collectors.toSet())
            )
        );

        // check that sending another join to node1 is a noop as the previous join is still in progress
        joinHelper.sendJoinRequest(node1, 0L, optionalJoin1);
        assertThat(capturingTransport.getCapturedRequestsAndClear().length, equalTo(0));

        // complete the previous join to node1
        completeJoinRequest(capturingTransport, capturedRequest1, mightSucceed);
        assertThat(joinHelper.getInFlightJoinStatuses(), equalTo(List.of(join2Status)));

        // check that sending another join to node1 now works again
        joinHelper.sendJoinRequest(node1, 0L, optionalJoin1);
        CapturedRequest[] capturedRequests1a = capturingTransport.getCapturedRequestsAndClear();
        assertThat(capturedRequests1a.length, equalTo(1));
        CapturedRequest capturedRequest1a = capturedRequests1a[0];
        assertEquals(node1, capturedRequest1a.node());

        // check that sending another join to node2 works if the optionalJoin is different
        Optional<Join> optionalJoin2a = optionalJoin2.isPresent() && randomBoolean()
            ? Optional.empty()
            : Optional.of(new Join(localNode, node2, randomNonNegativeLong(), randomNonNegativeLong(), randomNonNegativeLong()));
        joinHelper.sendJoinRequest(node2, 0L, optionalJoin2a);
        CapturedRequest[] capturedRequests2a = capturingTransport.getCapturedRequestsAndClear();
        assertThat(capturedRequests2a.length, equalTo(1));
        CapturedRequest capturedRequest2a = capturedRequests2a[0];
        assertEquals(node2, capturedRequest2a.node());

        // complete all the joins and check that isJoinPending is updated
        assertTrue(joinHelper.isJoinPending());
        assertTrue(transportService.nodeConnected(node1));
        assertTrue(transportService.nodeConnected(node2));

        completeJoinRequest(capturingTransport, capturedRequest2, mightSucceed);
        completeJoinRequest(capturingTransport, capturedRequest1a, mightSucceed);
        completeJoinRequest(capturingTransport, capturedRequest2a, mightSucceed);
        assertFalse(joinHelper.isJoinPending());

        if (mightSucceed) {
            // successful requests hold the connections open until the cluster state is applied
            joinHelper.onClusterStateApplied();
        }
        assertFalse(transportService.nodeConnected(node1));
        assertFalse(transportService.nodeConnected(node2));
    }

    private void completeJoinRequest(CapturingTransport capturingTransport, CapturedRequest request, boolean mightSucceed) {
        if (mightSucceed && randomBoolean()) {
            capturingTransport.handleResponse(request.requestId(), TransportResponse.Empty.INSTANCE);
        } else {
            capturingTransport.handleRemoteError(request.requestId(), new CoordinationStateRejectedException("dummy"));
        }
    }

    public void testFailedJoinAttemptLogLevel() {
        assertThat(JoinHelper.FailedJoinAttempt.getLogLevel(new TransportException("generic transport exception")), is(Level.INFO));

        assertThat(
            JoinHelper.FailedJoinAttempt.getLogLevel(
                new RemoteTransportException("remote transport exception with generic cause", new Exception())
            ),
            is(Level.INFO)
        );

        assertThat(
            JoinHelper.FailedJoinAttempt.getLogLevel(
                new RemoteTransportException("caused by CoordinationStateRejectedException", new CoordinationStateRejectedException("test"))
            ),
            is(Level.DEBUG)
        );

        assertThat(
            JoinHelper.FailedJoinAttempt.getLogLevel(
                new RemoteTransportException(
                    "caused by FailedToCommitClusterStateException",
                    new FailedToCommitClusterStateException("test")
                )
            ),
            is(Level.DEBUG)
        );

        assertThat(
            JoinHelper.FailedJoinAttempt.getLogLevel(
                new RemoteTransportException("caused by NotMasterException", new NotMasterException("test"))
            ),
            is(Level.DEBUG)
        );
    }

    public void testJoinFailureOnUnhealthyNodes() {
        DeterministicTaskQueue deterministicTaskQueue = new DeterministicTaskQueue();
        CapturingTransport capturingTransport = new HandshakingCapturingTransport();
        DiscoveryNode localNode = new DiscoveryNode("node0", buildNewFakeTransportAddress(), Version.CURRENT);
        TransportService transportService = capturingTransport.createTransportService(
            Settings.EMPTY,
            deterministicTaskQueue.getThreadPool(),
            TransportService.NOOP_TRANSPORT_INTERCEPTOR,
            x -> localNode,
            null,
            Collections.emptySet()
        );
        AtomicReference<StatusInfo> nodeHealthServiceStatus = new AtomicReference<>(new StatusInfo(UNHEALTHY, "unhealthy-info"));
        JoinHelper joinHelper = new JoinHelper(
            null,
            null,
            transportService,
            () -> 0L,
            (joinRequest, joinCallback) -> { throw new AssertionError(); },
            startJoinRequest -> { throw new AssertionError(); },
            (s, p, r) -> {},
            nodeHealthServiceStatus::get,
            new JoinReasonService(() -> 0L)
        );
        transportService.start();

        DiscoveryNode node1 = new DiscoveryNode("node1", buildNewFakeTransportAddress(), Version.CURRENT);
        DiscoveryNode node2 = new DiscoveryNode("node2", buildNewFakeTransportAddress(), Version.CURRENT);

        assertFalse(joinHelper.isJoinPending());

        // check that sending a join to node1 doesn't work
        Optional<Join> optionalJoin1 = randomBoolean()
            ? Optional.empty()
            : Optional.of(new Join(localNode, node1, randomNonNegativeLong(), randomNonNegativeLong(), randomNonNegativeLong()));
        joinHelper.sendJoinRequest(node1, randomNonNegativeLong(), optionalJoin1);
        CapturedRequest[] capturedRequests1 = capturingTransport.getCapturedRequestsAndClear();
        assertThat(capturedRequests1.length, equalTo(0));

        assertFalse(joinHelper.isJoinPending());

        // check that sending a join to node2 doesn't work
        Optional<Join> optionalJoin2 = randomBoolean()
            ? Optional.empty()
            : Optional.of(new Join(localNode, node2, randomNonNegativeLong(), randomNonNegativeLong(), randomNonNegativeLong()));

        transportService.start();
        joinHelper.sendJoinRequest(node2, randomNonNegativeLong(), optionalJoin2);

        CapturedRequest[] capturedRequests2 = capturingTransport.getCapturedRequestsAndClear();
        assertThat(capturedRequests2.length, equalTo(0));

        assertFalse(joinHelper.isJoinPending());

        nodeHealthServiceStatus.getAndSet(new StatusInfo(HEALTHY, "healthy-info"));
        // check that sending another join to node1 now works again
        joinHelper.sendJoinRequest(node1, 0L, optionalJoin1);
        CapturedRequest[] capturedRequests1a = capturingTransport.getCapturedRequestsAndClear();
        assertThat(capturedRequests1a.length, equalTo(1));
        CapturedRequest capturedRequest1a = capturedRequests1a[0];
        assertEquals(node1, capturedRequest1a.node());
    }

    private static class HandshakingCapturingTransport extends CapturingTransport {

        @Override
        protected void onSendRequest(long requestId, String action, TransportRequest request, DiscoveryNode node) {
            if (action.equals(HANDSHAKE_ACTION_NAME)) {
                handleResponse(
                    requestId,
                    new TransportService.HandshakeResponse(node.getVersion(), Build.CURRENT.hash(), node, ClusterName.DEFAULT)
                );
            } else {
                super.onSendRequest(requestId, action, request, node);
            }
        }
    }
}
