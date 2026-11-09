import ts from "typescript";
import type { ToolInfo } from "../types/index.js";

export interface SourceRiskyCall {
  kind: "command" | "database" | "eval" | "filesystem" | "network";
  callee: string;
  line: number;
  snippet: string;
}

export interface ExtractedSourceTool extends ToolInfo {
  sourceFile: string;
  declarationLine: number;
  handlerBody?: string;
  handlerStartLine?: number;
  handlerEndLine?: number;
  riskyCalls: SourceRiskyCall[];
}

export interface SourceRuntimeAnnotationDiff {
  toolName: string;
  annotation: "readOnlyHint" | "destructiveHint" | "idempotentHint" | "openWorldHint" | "title";
  sourceValue: unknown;
  runtimeValue: unknown;
}

export interface SourceRuntimeToolDiff {
  missingInRuntime: string[];
  missingInSource: string[];
  annotationDiffs: SourceRuntimeAnnotationDiff[];
}

const TOOL_REGISTRATION_NAMES = new Set(["tool", "registerTool", "addTool"]);
const ANNOTATION_KEYS: SourceRuntimeAnnotationDiff["annotation"][] = [
  "readOnlyHint",
  "destructiveHint",
  "idempotentHint",
  "openWorldHint",
  "title",
];

export function extractToolsFromSource(filePath: string, content: string): ExtractedSourceTool[] {
  const sourceFile = ts.createSourceFile(
    filePath,
    content,
    ts.ScriptTarget.Latest,
    true,
    scriptKindForPath(filePath),
  );
  const tools: ExtractedSourceTool[] = [];
  const aliases = collectToolRegistrationAliases(sourceFile);
  const metadataTables = collectObjectLiteralTables(sourceFile);

  function visit(node: ts.Node): void {
    if (ts.isCallExpression(node) && isToolRegistrationCall(node, aliases)) {
      const extracted = extractToolFromCall(sourceFile, filePath, node, metadataTables);
      if (extracted) tools.push(extracted);
    }
    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
  return tools;
}

export function compareSourceToRuntimeTools(
  sourceTools: ExtractedSourceTool[],
  runtimeTools: ToolInfo[],
): SourceRuntimeToolDiff {
  const sourceByName = new Map(sourceTools.map((tool) => [tool.name, tool]));
  const runtimeByName = new Map(runtimeTools.map((tool) => [tool.name, tool]));

  const missingInRuntime = sourceTools
    .filter((tool) => !runtimeByName.has(tool.name))
    .map((tool) => tool.name)
    .sort();

  const missingInSource = runtimeTools
    .filter((tool) => !sourceByName.has(tool.name))
    .map((tool) => tool.name)
    .sort();

  const annotationDiffs: SourceRuntimeAnnotationDiff[] = [];
  for (const [toolName, sourceTool] of sourceByName) {
    const runtimeTool = runtimeByName.get(toolName);
    if (!runtimeTool) continue;

    for (const annotation of ANNOTATION_KEYS) {
      const sourceValue = sourceTool.annotations?.[annotation];
      const runtimeValue = runtimeTool.annotations?.[annotation];
      if (sourceValue !== runtimeValue) {
        annotationDiffs.push({ toolName, annotation, sourceValue, runtimeValue });
      }
    }
  }

  return { missingInRuntime, missingInSource, annotationDiffs };
}

function scriptKindForPath(filePath: string): ts.ScriptKind {
  if (filePath.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (filePath.endsWith(".jsx")) return ts.ScriptKind.JSX;
  if (filePath.endsWith(".js") || filePath.endsWith(".mjs")) return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}

function isToolRegistrationCall(node: ts.CallExpression, aliases: Set<string>): boolean {
  const expression = node.expression;
  if (ts.isPropertyAccessExpression(expression)) {
    return TOOL_REGISTRATION_NAMES.has(expression.name.text);
  }
  if (ts.isElementAccessExpression(expression)) {
    const name = stringFromExpression(expression.argumentExpression);
    return name !== undefined && TOOL_REGISTRATION_NAMES.has(name);
  }
  if (ts.isIdentifier(expression)) {
    return expression.text === "registerTool" || expression.text === "addTool" || aliases.has(expression.text);
  }
  return false;
}

function extractToolFromCall(
  sourceFile: ts.SourceFile,
  filePath: string,
  node: ts.CallExpression,
  metadataTables: Map<string, Record<string, unknown>>,
): ExtractedSourceTool | null {
  const objectArgs = node.arguments.filter(ts.isObjectLiteralExpression);
  const metadata = node.arguments
    .map((arg) => ts.isObjectLiteralExpression(arg)
      ? objectLiteralToRecord(arg)
      : resolveMetadataReference(arg, metadataTables))
    .filter(isRecord);
  const name = extractToolName(node, metadata);
  if (!name) return null;

  const description = extractDescription(node, metadata);
  const inputSchema = extractInputSchema(objectArgs) ?? {};
  const annotations = extractAnnotations(metadata);
  const handler = [...node.arguments].reverse().find(isFunctionLikeExpression);
  const declarationLine = lineOf(sourceFile, node.getStart(sourceFile));
  const riskyCalls = handler ? collectRiskyCalls(sourceFile, handler) : [];

  return {
    name,
    description,
    inputSchema,
    annotations,
    sourceProtocol: "mcp",
    nativeType: "tool",
    sourceFile: filePath,
    declarationLine,
    handlerBody: handler?.getText(sourceFile),
    handlerStartLine: handler ? lineOf(sourceFile, handler.getStart(sourceFile)) : undefined,
    handlerEndLine: handler ? lineOf(sourceFile, handler.getEnd()) : undefined,
    riskyCalls,
  };
}

function extractToolName(node: ts.CallExpression, metadata: Record<string, unknown>[]): string | undefined {
  const firstArg = node.arguments[0];
  if (firstArg && ts.isStringLiteralLike(firstArg)) return firstArg.text;
  if (firstArg && ts.isNoSubstitutionTemplateLiteral(firstArg)) return firstArg.text;

  for (const record of metadata) {
    if (typeof record.name === "string" && record.name.trim()) return record.name;
    if (typeof record.id === "string" && record.id.trim()) return record.id;
  }

  return undefined;
}

function extractDescription(node: ts.CallExpression, metadata: Record<string, unknown>[]): string | undefined {
  for (const arg of node.arguments) {
    if (ts.isStringLiteralLike(arg) && arg !== node.arguments[0]) return arg.text;
  }

  for (const record of metadata) {
    if (typeof record.description === "string" && record.description.trim()) return record.description;
    if (typeof record.title === "string" && record.title.trim()) return record.title;
  }

  return undefined;
}

function extractInputSchema(objectArgs: ts.ObjectLiteralExpression[]): Record<string, unknown> | undefined {
  for (const objectArg of objectArgs) {
    const value = objectLiteralToRecord(objectArg);
    if (!isRecord(value)) continue;
    if (isRecord(value.inputSchema)) return value.inputSchema;
    if (isRecord(value.schema)) return value.schema;
    if (value.type === "object" || isRecord(value.properties)) return value;
  }

  return undefined;
}

function extractAnnotations(metadata: Record<string, unknown>[]): ToolInfo["annotations"] | undefined {
  for (const record of metadata) {
    const candidate = isRecord(record.annotations) ? record.annotations : record;
    const annotations: ToolInfo["annotations"] = {};

    for (const key of ANNOTATION_KEYS) {
      const value = candidate[key];
      if (typeof value === "boolean" || typeof value === "string") {
        annotations[key] = value as never;
      }
    }

    if (Object.keys(annotations).length > 0) return annotations;
  }

  return undefined;
}

function objectLiteralToRecord(node: ts.ObjectLiteralExpression): unknown {
  const record: Record<string, unknown> = {};

  for (const property of node.properties) {
    if (!ts.isPropertyAssignment(property)) continue;
    const key = propertyNameToString(property.name);
    if (!key) continue;
    record[key] = expressionToValue(property.initializer);
  }

  return record;
}

function collectToolRegistrationAliases(sourceFile: ts.SourceFile): Set<string> {
  const aliases = new Set<string>();

  function visit(node: ts.Node): void {
    if (ts.isVariableDeclaration(node)) {
      collectAliasFromVariable(node, aliases);
    }
    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
  return aliases;
}

function collectAliasFromVariable(node: ts.VariableDeclaration, aliases: Set<string>): void {
  if (ts.isIdentifier(node.name) && node.initializer && isToolRegistrationReference(node.initializer)) {
    aliases.add(node.name.text);
    return;
  }

  if (ts.isObjectBindingPattern(node.name)) {
    for (const element of node.name.elements) {
      const propertyName = element.propertyName
        ? bindingNameToString(element.propertyName)
        : bindingNameToString(element.name);
      if (!propertyName || !TOOL_REGISTRATION_NAMES.has(propertyName)) continue;
      if (ts.isIdentifier(element.name)) aliases.add(element.name.text);
    }
  }
}

function isToolRegistrationReference(node: ts.Expression): boolean {
  if (ts.isPropertyAccessExpression(node)) {
    return TOOL_REGISTRATION_NAMES.has(node.name.text);
  }
  if (ts.isElementAccessExpression(node)) {
    const name = stringFromExpression(node.argumentExpression);
    return name !== undefined && TOOL_REGISTRATION_NAMES.has(name);
  }
  if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === "bind") {
    return isToolRegistrationReference(node.expression.expression);
  }
  return false;
}

function collectObjectLiteralTables(sourceFile: ts.SourceFile): Map<string, Record<string, unknown>> {
  const tables = new Map<string, Record<string, unknown>>();

  function visit(node: ts.Node): void {
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.initializer &&
      ts.isObjectLiteralExpression(node.initializer)
    ) {
      const value = objectLiteralToRecord(node.initializer);
      if (isRecord(value)) tables.set(node.name.text, value);
    }
    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
  return tables;
}

function resolveMetadataReference(
  node: ts.Node,
  metadataTables: Map<string, Record<string, unknown>>,
): unknown {
  if (ts.isIdentifier(node)) {
    return metadataTables.get(node.text);
  }
  if (ts.isPropertyAccessExpression(node) && ts.isIdentifier(node.expression)) {
    const table = metadataTables.get(node.expression.text);
    const value = table?.[node.name.text];
    return isRecord(value) ? value : undefined;
  }
  if (ts.isElementAccessExpression(node) && ts.isIdentifier(node.expression)) {
    const key = stringFromExpression(node.argumentExpression);
    const table = metadataTables.get(node.expression.text);
    const value = key ? table?.[key] : undefined;
    return isRecord(value) ? value : undefined;
  }
  return undefined;
}

function propertyNameToString(name: ts.PropertyName): string | undefined {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name)) {
    return name.text;
  }
  return undefined;
}

function bindingNameToString(name: ts.BindingName | ts.PropertyName): string | undefined {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name)) {
    return name.text;
  }
  return undefined;
}

function stringFromExpression(expression: ts.Expression | undefined): string | undefined {
  if (!expression) return undefined;
  if (ts.isStringLiteralLike(expression)) return expression.text;
  if (ts.isNoSubstitutionTemplateLiteral(expression)) return expression.text;
  return undefined;
}

function expressionToValue(expression: ts.Expression): unknown {
  if (ts.isStringLiteralLike(expression)) return expression.text;
  if (ts.isNumericLiteral(expression)) return Number(expression.text);
  if (expression.kind === ts.SyntaxKind.TrueKeyword) return true;
  if (expression.kind === ts.SyntaxKind.FalseKeyword) return false;
  if (ts.isArrayLiteralExpression(expression)) return expression.elements.map(expressionToValue);
  if (ts.isObjectLiteralExpression(expression)) return objectLiteralToRecord(expression);
  if (
    ts.isPrefixUnaryExpression(expression) &&
    expression.operator === ts.SyntaxKind.MinusToken &&
    ts.isNumericLiteral(expression.operand)
  ) {
    return -Number(expression.operand.text);
  }
  return { source: expression.getText() };
}

function isFunctionLikeExpression(node: ts.Node): node is ts.ArrowFunction | ts.FunctionExpression {
  return ts.isArrowFunction(node) || ts.isFunctionExpression(node);
}

function collectRiskyCalls(sourceFile: ts.SourceFile, handler: ts.Node): SourceRiskyCall[] {
  const riskyCalls: SourceRiskyCall[] = [];

  function visit(node: ts.Node): void {
    if (ts.isCallExpression(node)) {
      const callee = node.expression.getText(sourceFile);
      const kind = classifyRiskyCall(callee);
      if (kind) {
        riskyCalls.push({
          kind,
          callee,
          line: lineOf(sourceFile, node.getStart(sourceFile)),
          snippet: node.getText(sourceFile).slice(0, 240),
        });
      }
    } else if (ts.isNewExpression(node)) {
      const callee = node.expression.getText(sourceFile);
      if (callee === "Function") {
        riskyCalls.push({
          kind: "eval",
          callee: "new Function",
          line: lineOf(sourceFile, node.getStart(sourceFile)),
          snippet: node.getText(sourceFile).slice(0, 240),
        });
      }
    }

    ts.forEachChild(node, visit);
  }

  visit(handler);
  return riskyCalls;
}

function classifyRiskyCall(callee: string): SourceRiskyCall["kind"] | null {
  if (/(^|\.)(exec|execSync|execFile|spawn|spawnSync)$/.test(callee)) return "command";
  if (/^(eval)$/.test(callee)) return "eval";
  if (/(^|\.)(fetch|get|post|request)$/.test(callee) || /^(axios|got|fetch)$/.test(callee)) return "network";
  if (/(^|\.)(readFile|writeFile|unlink|readdir|mkdir|rm|cp|stat|createReadStream|createWriteStream)(Sync)?$/.test(callee)) {
    return "filesystem";
  }
  if (/(^|\.)(query|execute|run|all|get)$/.test(callee)) return "database";
  return null;
}

function lineOf(sourceFile: ts.SourceFile, position: number): number {
  return sourceFile.getLineAndCharacterOfPosition(position).line + 1;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
