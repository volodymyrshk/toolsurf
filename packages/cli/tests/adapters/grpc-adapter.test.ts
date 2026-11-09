import { describe, test, expect } from "bun:test";
import { GrpcAdapter } from "../../src/adapters/grpc-adapter.js";
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const TEST_DIR = join(tmpdir(), "toolsurf-grpc-test-" + Date.now());

function setup() {
  mkdirSync(TEST_DIR, { recursive: true });
}
function teardown() {
  rmSync(TEST_DIR, { recursive: true, force: true });
}

const SERVICE_DEFS = [
  {
    service: "myapp.UserService",
    description: "User management service",
    methods: [
      {
        name: "GetUser",
        description: "Get a user by ID",
        inputType: "myapp.GetUserRequest",
        outputType: "myapp.User",
        clientStreaming: false,
        serverStreaming: false,
        fields: [
          { name: "id", type: "string", number: 1 },
        ],
      },
      {
        name: "ListUsers",
        description: "List all users",
        inputType: "myapp.ListUsersRequest",
        outputType: "myapp.ListUsersResponse",
        clientStreaming: false,
        serverStreaming: true,
        fields: [
          { name: "page_size", type: "int32", number: 1, optional: true },
          { name: "page_token", type: "string", number: 2, optional: true },
        ],
      },
      {
        name: "CreateUser",
        inputType: "myapp.CreateUserRequest",
        outputType: "myapp.User",
        fields: [
          { name: "name", type: "string", number: 1 },
          { name: "email", type: "string", number: 2 },
          { name: "roles", type: "string", number: 3, repeated: true },
        ],
      },
    ],
  },
  {
    service: "myapp.ChatService",
    methods: [
      {
        name: "StreamChat",
        inputType: "myapp.ChatMessage",
        outputType: "myapp.ChatMessage",
        clientStreaming: true,
        serverStreaming: true,
        fields: [
          { name: "content", type: "string", number: 1 },
          { name: "timestamp", type: "int64", number: 2 },
        ],
      },
    ],
  },
];

describe("gRPC Adapter", () => {
  test("has correct protocol metadata", () => {
    const adapter = new GrpcAdapter();
    expect(adapter.protocol).toBe("grpc");
    expect(adapter.displayName).toBe("gRPC");
  });

  test("parses service definitions from file", async () => {
    setup();
    try {
      const specFile = join(TEST_DIR, "services.json");
      writeFileSync(specFile, JSON.stringify(SERVICE_DEFS));

      const adapter = new GrpcAdapter();
      const caps = await adapter.connect({ params: { specFile } });

      expect(caps.protocol).toBe("grpc");
      expect(caps.tools.length).toBe(4); // 3 from UserService + 1 from ChatService

      // Check service discovery
      const services = caps.capabilities.services as string[];
      expect(services).toContain("myapp.UserService");
      expect(services).toContain("myapp.ChatService");
    } finally {
      teardown();
    }
  });

  test("normalizes method names as service/method", async () => {
    setup();
    try {
      const specFile = join(TEST_DIR, "services.json");
      writeFileSync(specFile, JSON.stringify(SERVICE_DEFS));

      const adapter = new GrpcAdapter();
      const caps = await adapter.connect({ params: { specFile } });

      const getUser = caps.tools.find((t) => t.name === "myapp.UserService/GetUser");
      expect(getUser).toBeDefined();
      expect(getUser!.description).toContain("Get a user by ID");
      expect(getUser!.sourceProtocol).toBe("grpc");
      expect(getUser!.endpointPath).toBe("myapp.UserService/GetUser");
    } finally {
      teardown();
    }
  });

  test("maps proto types to JSON Schema types", async () => {
    setup();
    try {
      const specFile = join(TEST_DIR, "services.json");
      writeFileSync(specFile, JSON.stringify(SERVICE_DEFS));

      const adapter = new GrpcAdapter();
      const caps = await adapter.connect({ params: { specFile } });

      const listUsers = caps.tools.find((t) => t.name === "myapp.UserService/ListUsers");
      const props = listUsers!.inputSchema.properties as Record<string, any>;

      // int32 → integer
      expect(props.page_size.type).toBe("integer");
      // string → string
      expect(props.page_token.type).toBe("string");
    } finally {
      teardown();
    }
  });

  test("handles repeated fields as arrays", async () => {
    setup();
    try {
      const specFile = join(TEST_DIR, "services.json");
      writeFileSync(specFile, JSON.stringify(SERVICE_DEFS));

      const adapter = new GrpcAdapter();
      const caps = await adapter.connect({ params: { specFile } });

      const createUser = caps.tools.find((t) => t.name === "myapp.UserService/CreateUser");
      const props = createUser!.inputSchema.properties as Record<string, any>;

      expect(props.roles.type).toBe("array");
      expect(props.roles.items.type).toBe("string");
    } finally {
      teardown();
    }
  });

  test("marks streaming methods in nativeType", async () => {
    setup();
    try {
      const specFile = join(TEST_DIR, "services.json");
      writeFileSync(specFile, JSON.stringify(SERVICE_DEFS));

      const adapter = new GrpcAdapter();
      const caps = await adapter.connect({ params: { specFile } });

      const listUsers = caps.tools.find((t) => t.name === "myapp.UserService/ListUsers");
      expect(listUsers!.nativeType).toBe("server-streaming");

      const streamChat = caps.tools.find((t) => t.name === "myapp.ChatService/StreamChat");
      expect(streamChat!.nativeType).toBe("bidirectional-streaming");
    } finally {
      teardown();
    }
  });

  test("marks required fields (non-optional)", async () => {
    setup();
    try {
      const specFile = join(TEST_DIR, "services.json");
      writeFileSync(specFile, JSON.stringify(SERVICE_DEFS));

      const adapter = new GrpcAdapter();
      const caps = await adapter.connect({ params: { specFile } });

      const getUser = caps.tools.find((t) => t.name === "myapp.UserService/GetUser");
      const required = getUser!.inputSchema.required as string[];
      expect(required).toContain("id");

      // ListUsers has optional fields → no required array or empty
      const listUsers = caps.tools.find((t) => t.name === "myapp.UserService/ListUsers");
      expect(listUsers!.inputSchema.required).toBeUndefined();
    } finally {
      teardown();
    }
  });

  test("throws on missing spec and url", async () => {
    const adapter = new GrpcAdapter();
    await expect(adapter.connect({ params: {} })).rejects.toThrow("requires a server address");
  });

  test("invoke throws without server", async () => {
    setup();
    try {
      const specFile = join(TEST_DIR, "services.json");
      writeFileSync(specFile, JSON.stringify(SERVICE_DEFS));

      const adapter = new GrpcAdapter();
      await adapter.connect({ params: { specFile } });
      await expect(
        adapter.invoke("myapp.UserService/GetUser", { id: "1" })
      ).rejects.toThrow("server address");
    } finally {
      teardown();
    }
  });
});
