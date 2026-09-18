#!/usr/bin/env node

/**
 * Have I Been Pwned MCP Server
 *
 * This server provides integration with the Have I Been Pwned API to check if:
 * - Email addresses have been found in data breaches
 * - Passwords have been exposed in data breaches (using k-anonymity)
 * - Accounts have been compromised in specific breaches
 */

import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import {
  Server,
  ProtocolError,
  ProtocolErrorCode,
} from "@modelcontextprotocol/server";
import axios, { AxiosInstance } from "axios";
import crypto from "crypto";

// API key should be provided as an environment variable
const API_KEY = process.env.HIBP_API_KEY;

// JSON Schema for a single HIBP breach record, as returned by the HIBP API and
// consumed by handleCheckEmail(), handleGetBreachDetails() and
// handleListAllBreaches() (fields beyond these are passed through untouched).
const BREACH_SCHEMA = {
  type: "object",
  properties: {
    Name: { type: "string" },
    Title: { type: "string" },
    Domain: { type: "string" },
    BreachDate: { type: "string" },
    Description: { type: "string" },
    DataClasses: {
      type: "array",
      items: { type: "string" },
      description: "Types of data compromised in the breach",
    },
    PwnCount: { type: "number" },
    IsVerified: { type: "boolean" },
    IsFabricated: { type: "boolean" },
    IsSensitive: { type: "boolean" },
    IsRetired: { type: "boolean" },
    IsSpamList: { type: "boolean" },
  },
  required: ["Name", "BreachDate", "Domain", "Description", "DataClasses"],
  additionalProperties: true,
};

// JSON Schema for check_email's structured result.
const CHECK_EMAIL_OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    found: { type: "boolean" },
    breach_count: { type: "number" },
    breaches: { type: "array", items: BREACH_SCHEMA },
  },
  required: ["found", "breach_count", "breaches"],
};

// JSON Schema for check_password's structured result.
const CHECK_PASSWORD_OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    pwned: { type: "boolean" },
    occurrences: {
      type: "number",
      description: "Number of times this password hash was seen in breach corpora",
    },
  },
  required: ["pwned", "occurrences"],
};

// JSON Schema for list_all_breaches's structured result.
const LIST_ALL_BREACHES_OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    count: { type: "number" },
    breaches: { type: "array", items: BREACH_SCHEMA },
  },
  required: ["count", "breaches"],
};

// JSON Schema for get_data_classes's structured result.
const DATA_CLASSES_OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    count: { type: "number" },
    data_classes: {
      type: "array",
      items: { type: "string" },
      description: "Types of data that can be compromised in a breach",
    },
  },
  required: ["count", "data_classes"],
};

// JSON Schema for get_latest_breach's structured result (a single breach).
const GET_LATEST_BREACH_OUTPUT_SCHEMA = BREACH_SCHEMA;

// JSON Schema for a single HIBP paste record, as returned by /pasteaccount/{email}.
const PASTE_SCHEMA = {
  type: "object",
  properties: {
    Source: { type: "string" },
    Id: { type: "string" },
    Title: { type: "string" },
    Date: { type: "string" },
    EmailCount: { type: "number" },
  },
  required: ["Source", "Id", "Date", "EmailCount"],
  additionalProperties: true,
};

// JSON Schema for get_pastes_for_account's structured result.
const GET_PASTES_OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    found: { type: "boolean" },
    paste_count: { type: "number" },
    pastes: { type: "array", items: PASTE_SCHEMA },
  },
  required: ["found", "paste_count", "pastes"],
};

// JSON Schema for check_stealer_logs_by_email's structured result.
const STEALER_LOGS_BY_EMAIL_OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    email: { type: "string" },
    found: { type: "boolean" },
    domain_count: { type: "number" },
    domains: {
      type: "array",
      items: { type: "string" },
      description:
        "Website domains where this email's credentials were captured by info-stealer malware",
    },
  },
  required: ["email", "found", "domain_count", "domains"],
};

// JSON Schema for check_stealer_logs_by_website_domain's structured result.
const STEALER_LOGS_BY_WEBSITE_DOMAIN_OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    domain: { type: "string" },
    found: { type: "boolean" },
    email_count: { type: "number" },
    emails: {
      type: "array",
      items: { type: "string" },
      description:
        "Email aliases whose credentials for this website were captured by info-stealer malware",
    },
  },
  required: ["domain", "found", "email_count", "emails"],
};

// JSON Schema for check_stealer_logs_by_email_domain's structured result.
const STEALER_LOGS_BY_EMAIL_DOMAIN_OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    domain: { type: "string" },
    found: { type: "boolean" },
    alias_count: { type: "number" },
    aliases: {
      type: "object",
      description:
        "Map of email alias (local part) to the website domains where that alias's credentials were captured",
      additionalProperties: {
        type: "array",
        items: { type: "string" },
      },
    },
  },
  required: ["domain", "found", "alias_count", "aliases"],
};

// Tools that call HIBP endpoints requiring a paid HIBP_API_KEY: lookups
// scoped to a specific account or domain (breach-by-account, pastes,
// stealer logs). The breach catalogue (get_breach_details,
// list_all_breaches, get_data_classes, get_latest_breach) and
// check_password are free per the HIBP API and are intentionally excluded.
const KEY_REQUIRED_TOOLS = new Set([
  "check_email",
  "get_pastes_for_account",
  "check_stealer_logs_by_email",
  "check_stealer_logs_by_website_domain",
  "check_stealer_logs_by_email_domain",
]);

// Friendly "no results" messages for tools where HIBP responds with 404 to
// mean "nothing found" rather than a real error.
const NOT_FOUND_MESSAGES: Record<string, (args: any) => string> = {
  get_pastes_for_account: () =>
    "Good news! No pastes were found containing this email address.",
  check_stealer_logs_by_email: () =>
    "Good news! This email address was not found in any known stealer logs.",
  check_stealer_logs_by_website_domain: (args: any) =>
    `No stealer log entries were found for the website domain: ${args?.domain}`,
  check_stealer_logs_by_email_domain: (args: any) =>
    `No stealer log entries were found for the email domain: ${args?.domain}`,
};

/**
 * Have I Been Pwned MCP Server implementation
 */
class HibpServer {
  private server: Server;
  private axiosInstance: AxiosInstance;

  constructor() {
    // Initialize the MCP server
    this.server = new Server(
      {
        name: "hibp-mcp-server",
        version: "0.1.0",
      },
      {
        capabilities: {
          tools: {},
        },
      },
    );

    // Check if API key is provided
    if (!API_KEY) {
      console.error("Warning: HIBP_API_KEY environment variable is not set");
      console.error("The server will start but API calls will fail");
    }

    // Initialize Axios instance for API calls
    this.axiosInstance = axios.create({
      baseURL: "https://haveibeenpwned.com/api/v3",
      headers: {
        "User-Agent": "hibp-mcp-server/0.1.0",
        "hibp-api-key": API_KEY,
      },
    });

    // Set up tool handlers
    this.setupToolHandlers();

    // Error handling
    this.server.onerror = (error) => console.error("[MCP Error]", error);
    process.on("SIGINT", async () => {
      await this.server.close();
      process.exit(0);
    });
  }

  /**
   * Set up handlers for the MCP tools
   */
  private setupToolHandlers() {
    // List available tools
    this.server.setRequestHandler("tools/list", async (): Promise<any> => ({
      tools: [
        {
          name: "check_email",
          description:
            "Check if an email address has been found in data breaches",
          inputSchema: {
            type: "object",
            properties: {
              email: {
                type: "string",
                description: "Email address to check",
              },
              include_unverified: {
                type: "boolean",
                description: "Include unverified breaches in the results",
                default: true,
              },
              truncate_response: {
                type: "boolean",
                description:
                  "Truncate the response to only include breach names",
                default: false,
              },
            },
            required: ["email"],
          },
          annotations: { readOnlyHint: true, openWorldHint: true },
          outputSchema: CHECK_EMAIL_OUTPUT_SCHEMA,
        },
        {
          name: "check_password",
          description:
            "Check if a password has been exposed in data breaches (using k-anonymity)",
          inputSchema: {
            type: "object",
            properties: {
              password: {
                type: "string",
                description: "Password to check",
              },
            },
            required: ["password"],
          },
          annotations: { readOnlyHint: true, openWorldHint: true },
          outputSchema: CHECK_PASSWORD_OUTPUT_SCHEMA,
        },
        {
          name: "get_breach_details",
          description: "Get details about a specific data breach",
          inputSchema: {
            type: "object",
            properties: {
              breach_name: {
                type: "string",
                description: "Name of the breach to get details for",
              },
            },
            required: ["breach_name"],
          },
          annotations: { readOnlyHint: true, openWorldHint: true },
          outputSchema: BREACH_SCHEMA,
        },
        {
          name: "list_all_breaches",
          description: "List all breaches in the system",
          inputSchema: {
            type: "object",
            properties: {
              domain: {
                type: "string",
                description: "Filter breaches by domain",
              },
            },
          },
          annotations: { readOnlyHint: true, openWorldHint: true },
          outputSchema: LIST_ALL_BREACHES_OUTPUT_SCHEMA,
        },
        {
          name: "get_data_classes",
          description:
            "List all the types of data (data classes) that can appear in a breach, e.g. 'Email addresses', 'Passwords'",
          inputSchema: {
            type: "object",
            properties: {},
          },
          annotations: { readOnlyHint: true, openWorldHint: true },
          outputSchema: DATA_CLASSES_OUTPUT_SCHEMA,
        },
        {
          name: "get_latest_breach",
          description:
            "Get the most recently added breach in the Have I Been Pwned system",
          inputSchema: {
            type: "object",
            properties: {},
          },
          annotations: { readOnlyHint: true, openWorldHint: true },
          outputSchema: GET_LATEST_BREACH_OUTPUT_SCHEMA,
        },
        {
          name: "get_pastes_for_account",
          description:
            "Get a list of pastes (e.g. Pastebin) that an email address has been found in. Requires a paid HIBP API key.",
          inputSchema: {
            type: "object",
            properties: {
              email: {
                type: "string",
                description: "Email address to check",
              },
            },
            required: ["email"],
          },
          annotations: { readOnlyHint: true, openWorldHint: true },
          outputSchema: GET_PASTES_OUTPUT_SCHEMA,
        },
        {
          name: "check_stealer_logs_by_email",
          description:
            "Check which website domains had credentials for this email address captured by info-stealer malware. This is a different, higher-fidelity threat category than classic breach lists. Requires a paid HIBP API key with Pro-tier access or higher.",
          inputSchema: {
            type: "object",
            properties: {
              email: {
                type: "string",
                description: "Email address to check",
              },
            },
            required: ["email"],
          },
          annotations: { readOnlyHint: true, openWorldHint: true },
          outputSchema: STEALER_LOGS_BY_EMAIL_OUTPUT_SCHEMA,
        },
        {
          name: "check_stealer_logs_by_website_domain",
          description:
            "Check which email aliases had credentials for this website domain captured by info-stealer malware. Requires a paid HIBP API key with Pro-tier access or higher.",
          inputSchema: {
            type: "object",
            properties: {
              domain: {
                type: "string",
                description: "Website domain to check, e.g. 'netflix.com'",
              },
            },
            required: ["domain"],
          },
          annotations: { readOnlyHint: true, openWorldHint: true },
          outputSchema: STEALER_LOGS_BY_WEBSITE_DOMAIN_OUTPUT_SCHEMA,
        },
        {
          name: "check_stealer_logs_by_email_domain",
          description:
            "Check which email aliases at this email domain (e.g. a company's domain) had credentials captured by info-stealer malware, and which websites those credentials were for. Requires a paid HIBP API key with Pro-tier access or higher, and the domain must be verified with HIBP.",
          inputSchema: {
            type: "object",
            properties: {
              domain: {
                type: "string",
                description: "Email domain to check, e.g. 'example.com'",
              },
            },
            required: ["domain"],
          },
          annotations: { readOnlyHint: true, openWorldHint: true },
          outputSchema: STEALER_LOGS_BY_EMAIL_DOMAIN_OUTPUT_SCHEMA,
        },
      ],
    }));

    // Handle tool calls
    this.server.setRequestHandler(
      "tools/call",
      async (request): Promise<any> => {
        // Check if API key is available for endpoints that require it.
        // Per the HIBP API, the breach catalogue (get_breach_details,
        // list_all_breaches, get_data_classes, get_latest_breach) and
        // check_password are free and do not require a key. Only lookups
        // tied to a specific account/domain (breach-by-account, pastes,
        // stealer logs) require a paid HIBP_API_KEY.
        if (!API_KEY && KEY_REQUIRED_TOOLS.has(request.params.name)) {
          return {
            content: [
              {
                type: "text",
                text: "Error: Have I Been Pwned API key is not configured. Please set the HIBP_API_KEY environment variable.",
              },
            ],
            isError: true,
          };
        }

        try {
          switch (request.params.name) {
            case "check_email":
              return await this.handleCheckEmail(request.params.arguments);
            case "check_password":
              return await this.handleCheckPassword(request.params.arguments);
            case "get_breach_details":
              return await this.handleGetBreachDetails(
                request.params.arguments,
              );
            case "list_all_breaches":
              return await this.handleListAllBreaches(request.params.arguments);
            case "get_data_classes":
              return await this.handleGetDataClasses();
            case "get_latest_breach":
              return await this.handleGetLatestBreach();
            case "get_pastes_for_account":
              return await this.handleGetPastesForAccount(
                request.params.arguments,
              );
            case "check_stealer_logs_by_email":
              return await this.handleCheckStealerLogsByEmail(
                request.params.arguments,
              );
            case "check_stealer_logs_by_website_domain":
              return await this.handleCheckStealerLogsByWebsiteDomain(
                request.params.arguments,
              );
            case "check_stealer_logs_by_email_domain":
              return await this.handleCheckStealerLogsByEmailDomain(
                request.params.arguments,
              );
            default:
              throw new ProtocolError(
                ProtocolErrorCode.MethodNotFound,
                `Unknown tool: ${request.params.name}`,
              );
          }
        } catch (error) {
          if (axios.isAxiosError(error)) {
            // Handle 404 for email not found in breaches
            if (
              error.response?.status === 404 &&
              request.params.name === "check_email"
            ) {
              return {
                content: [
                  {
                    type: "text",
                    text: "Good news! This email address has not been found in any known data breaches.",
                  },
                ],
              };
            }

            // HIBP returns 404 for the account/domain-scoped lookups below
            // when there are simply no results, not as an error condition.
            const notFoundMessageFn =
              NOT_FOUND_MESSAGES[
                request.params.name as keyof typeof NOT_FOUND_MESSAGES
              ];
            if (error.response?.status === 404 && notFoundMessageFn) {
              return {
                content: [
                  {
                    type: "text",
                    text: notFoundMessageFn(request.params.arguments),
                  },
                ],
              };
            }

            return {
              content: [
                {
                  type: "text",
                  text: `API Error: ${error.response?.data?.message || error.message} (Status: ${error.response?.status || "unknown"})`,
                },
              ],
              isError: true,
            };
          }
          throw error;
        }
      },
    );
  }

  /**
   * Handle the check_email tool
   */
  private async handleCheckEmail(args: any) {
    if (!args.email || typeof args.email !== "string") {
      throw new ProtocolError(
        ProtocolErrorCode.InvalidParams,
        "Email address is required",
      );
    }

    const params: Record<string, any> = {};

    if (args.include_unverified !== undefined) {
      params.includeUnverified = args.include_unverified;
    }

    if (args.truncate_response !== undefined) {
      params.truncateResponse = args.truncate_response;
    }

    const response = await this.axiosInstance.get(
      `/breachedaccount/${encodeURIComponent(args.email)}`,
      { params },
    );

    if (!response.data || response.data.length === 0) {
      return {
        content: [
          {
            type: "text",
            text: "Good news! This email address has not been found in any known data breaches.",
          },
        ],
      };
    }

    // Format the breach data for better readability
    const breaches = response.data;
    const breachCount = breaches.length;

    let summary = `⚠️ This email address was found in ${breachCount} data breach${breachCount > 1 ? "es" : ""}.\n\n`;

    if (args.truncate_response) {
      // If truncated, just list the breach names
      summary +=
        "Breaches: " + breaches.map((breach: any) => breach.Name).join(", ");
    } else {
      // Otherwise, provide detailed information
      summary += "Breach details:\n\n";

      breaches.forEach((breach: any, index: number) => {
        summary += `${index + 1}. ${breach.Name} (${breach.BreachDate})\n`;
        summary += `   Domain: ${breach.Domain}\n`;
        summary += `   Description: ${breach.Description}\n`;
        summary += `   Compromised data: ${breach.DataClasses.join(", ")}\n`;

        if (index < breaches.length - 1) {
          summary += "\n";
        }
      });

      summary += "\nRecommendations:\n";
      summary += "- Change your password for these services immediately\n";
      summary +=
        "- If you used the same password elsewhere, change those too\n";
      summary += "- Enable two-factor authentication where available\n";
      summary += "- Consider using a password manager";
    }

    return {
      content: [
        {
          type: "text",
          text: summary,
        },
      ],
      structuredContent: {
        found: true,
        breach_count: breachCount,
        breaches,
      },
    };
  }

  /**
   * Handle the check_password tool
   * Uses the k-anonymity model to check passwords without sending the full password
   */
  private async handleCheckPassword(args: any) {
    if (!args.password || typeof args.password !== "string") {
      throw new ProtocolError(
        ProtocolErrorCode.InvalidParams,
        "Password is required",
      );
    }

    // Hash the password with SHA-1
    const sha1Hash = crypto
      .createHash("sha1")
      .update(args.password)
      .digest("hex")
      .toUpperCase();

    // Get the first 5 characters (prefix) and the rest (suffix)
    const prefix = sha1Hash.substring(0, 5);
    const suffix = sha1Hash.substring(5);

    // Query the API with just the prefix (k-anonymity)
    const response = await axios.get(
      `https://api.pwnedpasswords.com/range/${prefix}`,
    );

    // Parse the response to find if our suffix is in the list
    const hashes = response.data.split("\n");
    let found = false;
    let occurrences = 0;

    for (const hash of hashes) {
      const [hashSuffix, count] = hash.split(":");

      if (hashSuffix.trim() === suffix) {
        found = true;
        occurrences = parseInt(count.trim(), 10);
        break;
      }
    }

    if (found) {
      return {
        content: [
          {
            type: "text",
            text: `⚠️ This password has been exposed in data breaches ${occurrences.toLocaleString()} times!\n\nRecommendations:\n- Stop using this password immediately\n- Change it on any site where you use it\n- Use a unique, strong password for each account\n- Consider using a password manager`,
          },
        ],
        structuredContent: {
          pwned: true,
          occurrences,
        },
      };
    } else {
      return {
        content: [
          {
            type: "text",
            text: "Good news! This password hasn't been found in any known data breaches. However, remember to use strong, unique passwords for each account and consider using a password manager.",
          },
        ],
      };
    }
  }

  /**
   * Handle the get_breach_details tool
   */
  private async handleGetBreachDetails(args: any) {
    if (!args.breach_name || typeof args.breach_name !== "string") {
      throw new ProtocolError(
        ProtocolErrorCode.InvalidParams,
        "Breach name is required",
      );
    }

    const response = await this.axiosInstance.get(
      `/breach/${encodeURIComponent(args.breach_name)}`,
    );

    if (!response.data) {
      return {
        content: [
          {
            type: "text",
            text: `No information found for breach: ${args.breach_name}`,
          },
        ],
      };
    }

    const breach = response.data;

    // Format the breach data for better readability
    let details = `# ${breach.Name} Data Breach\n\n`;
    details += `**Date:** ${breach.BreachDate}\n`;
    details += `**Domain:** ${breach.Domain}\n`;
    details += `**Accounts affected:** ${breach.PwnCount.toLocaleString()}\n`;
    details += `**Verified:** ${breach.IsVerified ? "Yes" : "No"}\n`;
    details += `**Data leaked:** ${breach.DataClasses.join(", ")}\n\n`;
    details += `**Description:**\n${breach.Description}\n\n`;

    if (breach.IsFabricated) {
      details +=
        "⚠️ Note: This breach has been flagged as potentially fabricated.\n\n";
    }

    if (breach.IsSensitive) {
      details += "⚠️ Note: This breach contains sensitive information.\n\n";
    }

    if (breach.IsRetired) {
      details +=
        "ℹ️ Note: This breach has been retired from active display.\n\n";
    }

    if (breach.IsSpamList) {
      details += "ℹ️ Note: This breach is from a spam list.\n\n";
    }

    details += "**Recommendations:**\n";
    details +=
      "- If you had an account on this service, change your password\n";
    details += "- If you used the same password elsewhere, change those too\n";
    details += "- Monitor your accounts for suspicious activity\n";
    details +=
      "- Be cautious of phishing attempts that may use this leaked information";

    return {
      content: [
        {
          type: "text",
          text: details,
        },
      ],
      structuredContent: breach,
    };
  }

  /**
   * Handle the list_all_breaches tool
   */
  private async handleListAllBreaches(args: any) {
    const params: Record<string, any> = {};

    if (args && args.domain) {
      params.domain = args.domain;
    }

    const response = await this.axiosInstance.get("/breaches", { params });

    if (!response.data || response.data.length === 0) {
      return {
        content: [
          {
            type: "text",
            text:
              args && args.domain
                ? `No breaches found for domain: ${args.domain}`
                : "No breaches found in the system.",
          },
        ],
      };
    }

    const breaches = response.data;

    // Format the breach list for better readability
    let summary =
      args && args.domain
        ? `Found ${breaches.length} breaches for domain ${args.domain}:\n\n`
        : `Found ${breaches.length} breaches in the system:\n\n`;

    // Sort breaches by date (newest first)
    breaches.sort((a: any, b: any) => {
      return (
        new Date(b.BreachDate).getTime() - new Date(a.BreachDate).getTime()
      );
    });

    breaches.forEach((breach: any, index: number) => {
      summary += `${index + 1}. ${breach.Name} (${breach.BreachDate})\n`;
      summary += `   Domain: ${breach.Domain}\n`;
      summary += `   Accounts affected: ${breach.PwnCount.toLocaleString()}\n`;
      summary += `   Compromised data: ${breach.DataClasses.join(", ")}\n`;

      if (index < breaches.length - 1) {
        summary += "\n";
      }
    });

    return {
      content: [
        {
          type: "text",
          text: summary,
        },
      ],
      structuredContent: {
        count: breaches.length,
        breaches,
      },
    };
  }

  /**
   * Handle the get_data_classes tool
   */
  private async handleGetDataClasses() {
    const response = await this.axiosInstance.get("/dataclasses");

    const dataClasses: string[] = response.data || [];

    let summary = `Have I Been Pwned tracks ${dataClasses.length} types of compromised data:\n\n`;
    summary += dataClasses.map((dc) => `- ${dc}`).join("\n");

    return {
      content: [
        {
          type: "text",
          text: summary,
        },
      ],
      structuredContent: {
        count: dataClasses.length,
        data_classes: dataClasses,
      },
    };
  }

  /**
   * Handle the get_latest_breach tool
   */
  private async handleGetLatestBreach() {
    const response = await this.axiosInstance.get("/latestbreach");

    const breach = response.data;

    if (!breach) {
      return {
        content: [
          {
            type: "text",
            text: "No breach information is currently available.",
          },
        ],
      };
    }

    let details = `# Latest Breach: ${breach.Name}\n\n`;
    details += `**Date:** ${breach.BreachDate}\n`;
    details += `**Domain:** ${breach.Domain}\n`;
    if (typeof breach.PwnCount === "number") {
      details += `**Accounts affected:** ${breach.PwnCount.toLocaleString()}\n`;
    }
    if (Array.isArray(breach.DataClasses)) {
      details += `**Data leaked:** ${breach.DataClasses.join(", ")}\n`;
    }
    details += `\n**Description:**\n${breach.Description}`;

    return {
      content: [
        {
          type: "text",
          text: details,
        },
      ],
      structuredContent: breach,
    };
  }

  /**
   * Handle the get_pastes_for_account tool
   * Requires a paid HIBP API key (Core, Pro, or High RPM tier).
   */
  private async handleGetPastesForAccount(args: any) {
    if (!args.email || typeof args.email !== "string") {
      throw new ProtocolError(
        ProtocolErrorCode.InvalidParams,
        "Email address is required",
      );
    }

    const response = await this.axiosInstance.get(
      `/pasteaccount/${encodeURIComponent(args.email)}`,
    );

    if (!response.data || response.data.length === 0) {
      return {
        content: [
          {
            type: "text",
            text: "Good news! No pastes were found containing this email address.",
          },
        ],
      };
    }

    const pastes = response.data;
    const pasteCount = pastes.length;

    let summary = `⚠️ This email address was found in ${pasteCount} paste${pasteCount > 1 ? "s" : ""}.\n\n`;

    pastes.forEach((paste: any, index: number) => {
      summary += `${index + 1}. Source: ${paste.Source}${paste.Title ? ` (${paste.Title})` : ""}\n`;
      summary += `   Date: ${paste.Date || "unknown"}\n`;
      summary += `   Email addresses in paste: ${paste.EmailCount}\n`;

      if (index < pastes.length - 1) {
        summary += "\n";
      }
    });

    return {
      content: [
        {
          type: "text",
          text: summary,
        },
      ],
      structuredContent: {
        found: true,
        paste_count: pasteCount,
        pastes,
      },
    };
  }

  /**
   * Handle the check_stealer_logs_by_email tool
   * Requires a paid HIBP API key with Pro-tier access or higher.
   */
  private async handleCheckStealerLogsByEmail(args: any) {
    if (!args.email || typeof args.email !== "string") {
      throw new ProtocolError(
        ProtocolErrorCode.InvalidParams,
        "Email address is required",
      );
    }

    const response = await this.axiosInstance.get(
      `/stealerlogsbyemail/${encodeURIComponent(args.email)}`,
    );

    const domains: string[] = response.data || [];

    if (domains.length === 0) {
      return {
        content: [
          {
            type: "text",
            text: "Good news! This email address was not found in any known stealer logs.",
          },
        ],
      };
    }

    let summary = `⚠️ This email address's credentials were found in stealer logs for ${domains.length} website${domains.length > 1 ? "s" : ""}.\n\n`;
    summary += "Websites: " + domains.join(", ");
    summary += "\n\nRecommendations:\n";
    summary += "- Change your password on these websites immediately\n";
    summary += "- Run an up-to-date malware scan on any device you use to log in\n";
    summary += "- Enable two-factor authentication where available";

    return {
      content: [
        {
          type: "text",
          text: summary,
        },
      ],
      structuredContent: {
        email: args.email,
        found: true,
        domain_count: domains.length,
        domains,
      },
    };
  }

  /**
   * Handle the check_stealer_logs_by_website_domain tool
   * Requires a paid HIBP API key with Pro-tier access or higher.
   */
  private async handleCheckStealerLogsByWebsiteDomain(args: any) {
    if (!args.domain || typeof args.domain !== "string") {
      throw new ProtocolError(
        ProtocolErrorCode.InvalidParams,
        "Website domain is required",
      );
    }

    const response = await this.axiosInstance.get(
      `/stealerlogsbywebsitedomain/${encodeURIComponent(args.domain)}`,
    );

    const emails: string[] = response.data || [];

    if (emails.length === 0) {
      return {
        content: [
          {
            type: "text",
            text: `No stealer log entries were found for the website domain: ${args.domain}`,
          },
        ],
      };
    }

    let summary = `⚠️ Found ${emails.length} email alias${emails.length > 1 ? "es" : ""} with credentials for ${args.domain} captured in stealer logs.\n\n`;
    summary += "Email aliases: " + emails.join(", ");

    return {
      content: [
        {
          type: "text",
          text: summary,
        },
      ],
      structuredContent: {
        domain: args.domain,
        found: true,
        email_count: emails.length,
        emails,
      },
    };
  }

  /**
   * Handle the check_stealer_logs_by_email_domain tool
   * Requires a paid HIBP API key with Pro-tier access or higher, and the
   * domain must be verified with HIBP.
   */
  private async handleCheckStealerLogsByEmailDomain(args: any) {
    if (!args.domain || typeof args.domain !== "string") {
      throw new ProtocolError(
        ProtocolErrorCode.InvalidParams,
        "Email domain is required",
      );
    }

    const response = await this.axiosInstance.get(
      `/stealerlogsbyemaildomain/${encodeURIComponent(args.domain)}`,
    );

    const aliases: Record<string, string[]> = response.data || {};
    const aliasNames = Object.keys(aliases);

    if (aliasNames.length === 0) {
      return {
        content: [
          {
            type: "text",
            text: `No stealer log entries were found for the email domain: ${args.domain}`,
          },
        ],
      };
    }

    let summary = `⚠️ Found ${aliasNames.length} email alias${aliasNames.length > 1 ? "es" : ""} at ${args.domain} with credentials captured in stealer logs.\n\n`;

    aliasNames.forEach((alias, index) => {
      summary += `${index + 1}. ${alias}@${args.domain}: ${aliases[alias].join(", ")}\n`;
    });

    return {
      content: [
        {
          type: "text",
          text: summary,
        },
      ],
      structuredContent: {
        domain: args.domain,
        found: true,
        alias_count: aliasNames.length,
        aliases,
      },
    };
  }

  /**
   * Start the server
   */
  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error("Have I Been Pwned MCP server running on stdio");
  }
}

// Create and start the server
const server = new HibpServer();
server.run().catch(console.error);
