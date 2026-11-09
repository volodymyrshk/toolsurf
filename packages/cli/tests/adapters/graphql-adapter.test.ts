import { describe, test, expect } from "bun:test";
import { GraphQlAdapter } from "../../src/adapters/graphql-adapter.js";
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const TEST_DIR = join(tmpdir(), "toolsurf-graphql-test-" + Date.now());

function setup() {
  mkdirSync(TEST_DIR, { recursive: true });
}
function teardown() {
  rmSync(TEST_DIR, { recursive: true, force: true });
}

const INTROSPECTION_RESULT = {
  __schema: {
    queryType: { name: "Query" },
    mutationType: { name: "Mutation" },
    subscriptionType: null,
    types: [
      {
        kind: "OBJECT",
        name: "Query",
        description: null,
        fields: [
          {
            name: "user",
            description: "Get a user by ID",
            isDeprecated: false,
            args: [
              {
                name: "id",
                description: "User ID",
                type: { kind: "NON_NULL", name: null, ofType: { kind: "SCALAR", name: "ID", ofType: null } },
              },
            ],
            type: { kind: "OBJECT", name: "User", ofType: null },
          },
          {
            name: "users",
            description: "List users",
            isDeprecated: false,
            args: [
              {
                name: "limit",
                description: "Max results",
                type: { kind: "SCALAR", name: "Int", ofType: null },
              },
              {
                name: "filter",
                description: "Filter input",
                type: { kind: "INPUT_OBJECT", name: "UserFilter", ofType: null },
              },
            ],
            type: {
              kind: "LIST",
              name: null,
              ofType: { kind: "OBJECT", name: "User", ofType: null },
            },
          },
          {
            name: "__schema",
            description: "Introspection",
            isDeprecated: false,
            args: [],
            type: { kind: "OBJECT", name: "__Schema", ofType: null },
          },
        ],
      },
      {
        kind: "OBJECT",
        name: "Mutation",
        description: null,
        fields: [
          {
            name: "createUser",
            description: "Create a new user",
            isDeprecated: false,
            args: [
              {
                name: "name",
                description: "User name",
                type: { kind: "NON_NULL", name: null, ofType: { kind: "SCALAR", name: "String", ofType: null } },
              },
              {
                name: "email",
                description: "Email address",
                type: { kind: "NON_NULL", name: null, ofType: { kind: "SCALAR", name: "String", ofType: null } },
              },
            ],
            type: { kind: "OBJECT", name: "User", ofType: null },
          },
          {
            name: "deleteUser",
            description: "Delete a user",
            isDeprecated: false,
            args: [
              {
                name: "id",
                type: { kind: "NON_NULL", name: null, ofType: { kind: "SCALAR", name: "ID", ofType: null } },
              },
            ],
            type: { kind: "SCALAR", name: "Boolean", ofType: null },
          },
        ],
      },
      {
        kind: "INPUT_OBJECT",
        name: "UserFilter",
        description: "Filter for user queries",
        inputFields: [
          {
            name: "role",
            description: "Filter by role",
            type: { kind: "SCALAR", name: "String", ofType: null },
          },
          {
            name: "active",
            description: "Only active users",
            type: { kind: "SCALAR", name: "Boolean", ofType: null },
          },
        ],
      },
    ],
  },
};

describe("GraphQL Adapter", () => {
  test("has correct protocol metadata", () => {
    const adapter = new GraphQlAdapter();
    expect(adapter.protocol).toBe("graphql");
    expect(adapter.displayName).toBe("GraphQL");
  });

  test("parses introspection result from file", async () => {
    setup();
    try {
      const specFile = join(TEST_DIR, "introspection.json");
      writeFileSync(specFile, JSON.stringify(INTROSPECTION_RESULT));

      const adapter = new GraphQlAdapter();
      const caps = await adapter.connect({ params: { specFile } });

      expect(caps.protocol).toBe("graphql");
      // 2 query fields (user, users — __schema skipped) + 2 mutation fields
      expect(caps.tools.length).toBe(4);

      // Check query tools
      const queryUser = caps.tools.find((t) => t.name === "query_user");
      expect(queryUser).toBeDefined();
      expect(queryUser!.description).toBe("Get a user by ID");
      expect(queryUser!.sourceProtocol).toBe("graphql");
      expect(queryUser!.nativeType).toBe("query");
      // id is NON_NULL so should be required
      const required = queryUser!.inputSchema.required as string[];
      expect(required).toContain("id");

      const queryUsers = caps.tools.find((t) => t.name === "query_users");
      expect(queryUsers).toBeDefined();
      // limit is optional Int → should be integer
      const props = queryUsers!.inputSchema.properties as Record<string, any>;
      expect(props.limit.type).toBe("integer");
      // filter is INPUT_OBJECT → should be object with properties
      expect(props.filter.type).toBe("object");
      expect(props.filter.properties.role.type).toBe("string");
      expect(props.filter.properties.active.type).toBe("boolean");
    } finally {
      teardown();
    }
  });

  test("parses mutation tools", async () => {
    setup();
    try {
      const specFile = join(TEST_DIR, "introspection.json");
      writeFileSync(specFile, JSON.stringify(INTROSPECTION_RESULT));

      const adapter = new GraphQlAdapter();
      const caps = await adapter.connect({ params: { specFile } });

      const createUser = caps.tools.find((t) => t.name === "mutation_createUser");
      expect(createUser).toBeDefined();
      expect(createUser!.nativeType).toBe("mutation");
      expect(createUser!.httpMethod).toBe("MUTATION");
      // name and email are NON_NULL
      const required = createUser!.inputSchema.required as string[];
      expect(required).toContain("name");
      expect(required).toContain("email");
    } finally {
      teardown();
    }
  });

  test("handles data-wrapped introspection result", async () => {
    setup();
    try {
      const specFile = join(TEST_DIR, "wrapped.json");
      writeFileSync(specFile, JSON.stringify({ data: INTROSPECTION_RESULT }));

      const adapter = new GraphQlAdapter();
      const caps = await adapter.connect({ params: { specFile } });
      expect(caps.tools.length).toBe(4);
    } finally {
      teardown();
    }
  });

  test("throws on missing endpoint and spec", async () => {
    const adapter = new GraphQlAdapter();
    await expect(adapter.connect({ params: {} })).rejects.toThrow("requires an endpoint URL");
  });

  test("invoke throws without URL", async () => {
    setup();
    try {
      const specFile = join(TEST_DIR, "introspection.json");
      writeFileSync(specFile, JSON.stringify(INTROSPECTION_RESULT));

      const adapter = new GraphQlAdapter();
      await adapter.connect({ params: { specFile } });
      await expect(adapter.invoke("query_user", { id: "1" })).rejects.toThrow("endpoint URL");
    } finally {
      teardown();
    }
  });
});
