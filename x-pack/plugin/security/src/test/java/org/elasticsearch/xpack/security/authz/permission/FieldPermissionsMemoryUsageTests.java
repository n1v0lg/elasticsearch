/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authz.permission;

import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.xpack.core.security.authz.permission.FieldPermissions;
import org.elasticsearch.xpack.core.security.authz.permission.FieldPermissionsDefinition;
import org.openjdk.jol.info.GraphLayout;

public class FieldPermissionsMemoryUsageTests extends ESTestCase {

    public void testMemoryUsage() {
        var smallFls = new FieldPermissions(
            new FieldPermissionsDefinition(new String[] { "field_0", "field_1", "field_2" }, new String[] {})
        );
        System.out.println(GraphLayout.parseInstance(smallFls).toPrintable());
        long currentTotalSize = GraphLayout.parseInstance(smallFls).totalSize();
        System.out.println("Total size: " + currentTotalSize + " bytes");

        String[] grant = new String[1000];
        for (int i = 0; i < 1000; i++) {
            grant[i] = "field_" + i;
        }
        var bigFls = new FieldPermissions(new FieldPermissionsDefinition(grant, new String[] {}));
        currentTotalSize = GraphLayout.parseInstance(bigFls).totalSize();
        System.out.println("Total size: " + currentTotalSize + " bytes");
    }

}
