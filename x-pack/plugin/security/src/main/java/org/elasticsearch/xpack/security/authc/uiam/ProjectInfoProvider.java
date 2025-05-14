/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authc.uiam;

import co.elastic.elasticsearch.serverless.constants.ProjectType;

import org.elasticsearch.common.settings.Settings;

import static co.elastic.elasticsearch.serverless.constants.ServerlessSharedSettings.PROJECT_ID;
import static co.elastic.elasticsearch.serverless.constants.ServerlessSharedSettings.PROJECT_TYPE;

public class ProjectInfoProvider {

    private final String projectId;
    private final ProjectType projectType;
    private final String organizationId;

    public ProjectInfoProvider(Settings settings) {
        this.projectId = PROJECT_ID.get(settings);
        this.projectType = PROJECT_TYPE.get(settings);
        this.organizationId = "1998";
    }

    ProjectInfo get() {
        return new ProjectInfo(projectId, organizationId, toName(projectType));
    }

    String toName(ProjectType projectType) {
        // switch on project type
        // return the name of the project type
        switch (projectType) {
            case ELASTICSEARCH_GENERAL_PURPOSE, ELASTICSEARCH_SEARCH, ELASTICSEARCH_VECTOR, ELASTICSEARCH_TIMESERIES -> {
                return "elasticsearch";
            }
            case OBSERVABILITY -> {
                return "observability";
            }
            case SECURITY -> {
                return "security";
            }
            default -> throw new IllegalStateException("Unexpected value: " + projectType);
        }
    }

    record ProjectInfo(String projectId, String organizationId, String projectType) {}
}
