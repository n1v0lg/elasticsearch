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
        var current = new FieldPermissions(new FieldPermissionsDefinition(new String[] { "field_0" }, new String[] {}));
        var currentTotalSize = GraphLayout.parseInstance(current).totalSize();
        System.out.println("Total size: " + currentTotalSize + " bytes");
    }

}
