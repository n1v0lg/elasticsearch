/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.authc;

import org.elasticsearch.Version;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.xcontent.XContentBuilder;
import org.elasticsearch.xcontent.XContentFactory;
import org.elasticsearch.xcontent.XContentParser;
import org.elasticsearch.xcontent.XContentParserConfiguration;
import org.elasticsearch.xcontent.XContentType;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptorsIntersection;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public record RemoteAccessAuthentication(Authentication authentication, Collection<BytesReference> roleDescriptorsBytesIntersection) {
    public static final String REMOTE_ACCESS_AUTHENTICATION_HEADER_KEY = "_remote_access_authentication";

    public static void writeToContextAsRemoteAccessAuthentication(
        final ThreadContext ctx,
        final Authentication authentication,
        final RoleDescriptorsIntersection roleDescriptorsIntersection
    ) throws IOException {
        ensureContextDoesNotContainRemoteAccessAuthentication(ctx);
        ctx.putHeader(REMOTE_ACCESS_AUTHENTICATION_HEADER_KEY, encode(authentication, roleDescriptorsIntersection));
    }

    public static RemoteAccessAuthentication readFromContext(final ThreadContext ctx) throws IOException {
        return decode(ctx.getHeader(REMOTE_ACCESS_AUTHENTICATION_HEADER_KEY));
    }

    public static Set<RoleDescriptor> parseRoleDescriptorsBytes(final BytesReference roleDescriptorsBytes) {
        try (
            XContentParser parser = XContentHelper.createParser(XContentParserConfiguration.EMPTY, roleDescriptorsBytes, XContentType.JSON)
        ) {
            final List<RoleDescriptor> roleDescriptors = new ArrayList<>();
            parser.nextToken();
            while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
                parser.nextToken();
                final String roleName = parser.currentName();
                roleDescriptors.add(RoleDescriptor.parse(roleName, parser, false));
            }
            return Set.copyOf(roleDescriptors);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static String encode(final Authentication authentication, final RoleDescriptorsIntersection roleDescriptorsIntersection)
        throws IOException {
        // If we ever lift this restriction, we need to ensure that the serialization of each set of role descriptors to raw bytes is
        // deterministic. We can do so by sorting the role descriptors before serializing.
        assert roleDescriptorsIntersection.roleDescriptorsList().stream().noneMatch(rds -> rds.size() > 1)
            : "sets with more than one role descriptor are not supported for remote access authentication";
        final BytesStreamOutput out = new BytesStreamOutput();
        out.setVersion(authentication.getEffectiveSubject().getVersion());
        Version.writeVersion(authentication.getEffectiveSubject().getVersion(), out);
        authentication.writeTo(out);
        out.writeCollection(roleDescriptorsIntersection.roleDescriptorsList(), (innerStreamOutput, roleDescriptors) -> {
            final XContentBuilder builder = XContentFactory.jsonBuilder();
            builder.startObject();
            for (RoleDescriptor roleDescriptor : roleDescriptors) {
                builder.field(roleDescriptor.getName(), roleDescriptor);
            }
            builder.endObject();
            innerStreamOutput.writeBytesReference(BytesReference.bytes(builder));
        });
        return Base64.getEncoder().encodeToString(BytesReference.toBytes(out.bytes()));
    }

    private static RemoteAccessAuthentication decode(final String header) throws IOException {
        Objects.requireNonNull(header);
        final byte[] bytes = Base64.getDecoder().decode(header);
        final StreamInput in = StreamInput.wrap(bytes);
        final Version version = Version.readVersion(in);
        in.setVersion(version);
        final Authentication authentication = new Authentication(in);
        final List<BytesReference> roleDescriptorsBytesIntersection = in.readImmutableList(StreamInput::readBytesReference);
        return new RemoteAccessAuthentication(authentication, roleDescriptorsBytesIntersection);
    }

    private static void ensureContextDoesNotContainRemoteAccessAuthentication(final ThreadContext ctx) {
        if (ctx.getHeader(REMOTE_ACCESS_AUTHENTICATION_HEADER_KEY) != null) {
            throw new IllegalStateException(
                "remote access authentication [" + REMOTE_ACCESS_AUTHENTICATION_HEADER_KEY + "] is already present in the context"
            );
        }
    }
}
