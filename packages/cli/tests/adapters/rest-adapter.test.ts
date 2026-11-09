import { describe, test, expect } from "bun:test";
import { RestApiAdapter } from "../../src/adapters/rest-adapter.js";
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const TEST_DIR = join(tmpdir(), "toolsurf-rest-test-" + Date.now());

function setup() {
  mkdirSync(TEST_DIR, { recursive: true });
}
function teardown() {
  rmSync(TEST_DIR, { recursive: true, force: true });
}

const MINIMAL_OPENAPI = {
  openapi: "3.0.0",
  info: { title: "Test API", version: "1.0.0" },
  servers: [{ url: "https://api.example.com" }],
  paths: {
    "/users": {
      get: {
        operationId: "listUsers",
        summary: "List all users",
        parameters: [
          {
            name: "limit",
            in: "query",
            schema: { type: "integer" },
          },
        ],
      },
      post: {
        operationId: "createUser",
        summary: "Create a user",
        requestBody: {
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  name: { type: "string" },
                  email: { type: "string" },
                },
                required: ["name", "email"],
              },
            },
          },
        },
      },
    },
    "/users/{id}": {
      get: {
        operationId: "getUser",
        summary: "Get user by ID",
        parameters: [
          {
            name: "id",
            in: "path",
            required: true,
            schema: { type: "string" },
          },
        ],
      },
      delete: {
        operationId: "deleteUser",
        summary: "Delete a user",
        parameters: [
          {
            name: "id",
            in: "path",
            required: true,
            schema: { type: "string" },
          },
        ],
      },
    },
  },
};

describe("REST API Adapter", () => {
  test("has correct protocol metadata", () => {
    const adapter = new RestApiAdapter();
    expect(adapter.protocol).toBe("rest-api");
    expect(adapter.displayName).toBe("REST API (OpenAPI/Swagger)");
  });

  test("parses OpenAPI 3.0 spec", async () => {
    setup();
    try {
      const specFile = join(TEST_DIR, "openapi.json");
      writeFileSync(specFile, JSON.stringify(MINIMAL_OPENAPI));

      const adapter = new RestApiAdapter();
      const caps = await adapter.connect({ params: { specFile } });

      expect(caps.tools.length).toBe(4);
      expect(caps.serverInfo.name).toBe("Test API");
      expect(caps.serverInfo.version).toBe("1.0.0");
      expect(caps.protocol).toBe("rest-api");

      // Check specific operations
      const listUsers = caps.tools.find((t) => t.name === "listUsers");
      expect(listUsers).toBeDefined();
      expect(listUsers!.httpMethod).toBe("GET");
      expect(listUsers!.endpointPath).toBe("/users");
      expect(listUsers!.sourceProtocol).toBe("rest-api");
      expect(listUsers!.nativeType).toBe("endpoint");

      const createUser = caps.tools.find((t) => t.name === "createUser");
      expect(createUser).toBeDefined();
      expect(createUser!.httpMethod).toBe("POST");
      // Should have name and email from requestBody
      const props = createUser!.inputSchema.properties as Record<string, any>;
      expect(props.name).toBeDefined();
      expect(props.email).toBeDefined();

      const deleteUser = caps.tools.find((t) => t.name === "deleteUser");
      expect(deleteUser).toBeDefined();
      expect(deleteUser!.httpMethod).toBe("DELETE");
    } finally {
      teardown();
    }
  });

  test("parses Swagger 2.0 spec", async () => {
    setup();
    try {
      const swagger2 = {
        swagger: "2.0",
        info: { title: "Legacy API", version: "2.0.0" },
        host: "api.legacy.com",
        basePath: "/v2",
        schemes: ["https"],
        paths: {
          "/items": {
            get: {
              operationId: "listItems",
              summary: "List items",
              parameters: [
                { name: "q", in: "query", type: "string" },
              ],
            },
          },
        },
      };

      const specFile = join(TEST_DIR, "swagger.json");
      writeFileSync(specFile, JSON.stringify(swagger2));

      const adapter = new RestApiAdapter();
      const caps = await adapter.connect({ params: { specFile } });

      expect(caps.tools.length).toBe(1);
      expect(caps.tools[0].name).toBe("listItems");
      expect(caps.protocolVersion).toContain("Swagger");
    } finally {
      teardown();
    }
  });

  test("generates operationId when missing", async () => {
    setup();
    try {
      const spec = {
        openapi: "3.0.0",
        info: { title: "No IDs", version: "1.0.0" },
        paths: {
          "/data": {
            get: { summary: "Get data" },
          },
        },
      };

      const specFile = join(TEST_DIR, "no-ids.json");
      writeFileSync(specFile, JSON.stringify(spec));

      const adapter = new RestApiAdapter();
      const caps = await adapter.connect({ params: { specFile } });

      expect(caps.tools.length).toBe(1);
      expect(caps.tools[0].name).toBe("GET_data");
    } finally {
      teardown();
    }
  });

  test("throws on missing spec", async () => {
    const adapter = new RestApiAdapter();
    await expect(adapter.connect({ params: {} })).rejects.toThrow("requires an OpenAPI");
  });

  test("handles path parameters with required flag", async () => {
    setup();
    try {
      const specFile = join(TEST_DIR, "openapi.json");
      writeFileSync(specFile, JSON.stringify(MINIMAL_OPENAPI));

      const adapter = new RestApiAdapter();
      const caps = await adapter.connect({ params: { specFile } });

      const getUser = caps.tools.find((t) => t.name === "getUser");
      const required = getUser!.inputSchema.required as string[];
      expect(required).toContain("id");
    } finally {
      teardown();
    }
  });
});
