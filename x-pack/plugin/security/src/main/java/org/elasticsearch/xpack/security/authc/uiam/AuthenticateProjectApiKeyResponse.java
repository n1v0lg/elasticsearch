/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authc.uiam;

import org.elasticsearch.xcontent.ObjectParser;
import org.elasticsearch.xcontent.ParseField;
import org.elasticsearch.xcontent.XContentParser;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

public final class AuthenticateProjectApiKeyResponse {
    private static final ObjectParser<AuthenticateProjectApiKeyResponse, Void> PARSER = new ObjectParser<>(
        "authenticate_project_api_key_response"
    );

    // {"type":"api-key","api_key_id":"123","organization_id":"1998","application_roles":["appRole1","appRole2"]}
    static {
        PARSER.declareString(AuthenticateProjectApiKeyResponse::setType, new ParseField("type"));
        PARSER.declareString(AuthenticateProjectApiKeyResponse::setId, new ParseField("api_key_id"));
        PARSER.declareString(AuthenticateProjectApiKeyResponse::setOrganizationId, new ParseField("organization_id"));
        PARSER.declareStringArray(AuthenticateProjectApiKeyResponse::setApplicationRoles, new ParseField("application_roles"));
    }

    public static AuthenticateProjectApiKeyResponse fromXContent(XContentParser parser) throws IOException {
        AuthenticateProjectApiKeyResponse response = new AuthenticateProjectApiKeyResponse();
        PARSER.parse(parser, response, null);
        return response;
    }

    private String type;
    private String id;
    private String organizationId;
    private List<String> applicationRoles;

    AuthenticateProjectApiKeyResponse() {
    }

    public void setType(String type) {
        this.type = type;
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setOrganizationId(String organizationId) {
        this.organizationId = organizationId;
    }

    public void setApplicationRoles(List<String> applicationRoles) {
        this.applicationRoles = applicationRoles;
    }

    public String setType() {
        return type;
    }

    public String id() {
        return id;
    }

    public String organizationId() {
        return organizationId;
    }

    public List<String> applicationRoles() {
        return applicationRoles;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (AuthenticateProjectApiKeyResponse) obj;
        return Objects.equals(this.type, that.type)
            && Objects.equals(this.id, that.id)
            && Objects.equals(this.organizationId, that.organizationId)
            && Objects.equals(this.applicationRoles, that.applicationRoles);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, id, organizationId, applicationRoles);
    }

    @Override
    public String toString() {
        return "Response["
            + "type="
            + type
            + ", "
            + "id="
            + id
            + ", "
            + "organizationId="
            + organizationId
            + ", "
            + "applicationRoles="
            + applicationRoles
            + ']';
    }

}
