#!/usr/bin/env node

/**
 * Have I Been Pwned MCP Server
 *
 * This server provides integration with the Have I Been Pwned API to check if:
 * - Email addresses have been found in data breaches
 * - Passwords have been exposed in data breaches (using k-anonymity)
 * - Accounts have been compromised in specific breaches
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import axios, { AxiosInstance } from "axios";
import crypto from "crypto";

// API key should be provided as an environment variable
const API_KEY = process.env.HIBP_API_KEY;

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
      }
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
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: "check_email",
          description: "Check if an email address has been found in data breaches",
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
                description: "Truncate the response to only include breach names",
                default: false,
              },
            },
            required: ["email"],
          },
        },
        {
          name: "check_password",
          description: "Check if a password has been exposed in data breaches (using k-anonymity)",
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
        },
      ],
    }));

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      // Check if API key is available for endpoints that require it
      if (!API_KEY && request.params.name !== "check_password") {
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
            return await this.handleGetBreachDetails(request.params.arguments);
          case "list_all_breaches":
            return await this.handleListAllBreaches(request.params.arguments);
          default:
            throw new McpError(
              ErrorCode.MethodNotFound,
              `Unknown tool: ${request.params.name}`
            );
        }
      } catch (error) {
        if (axios.isAxiosError(error)) {
          // Handle 404 for email not found in breaches
          if (error.response?.status === 404 && request.params.name === "check_email") {
            return {
              content: [
                {
                  type: "text",
                  text: "Good news! This email address has not been found in any known data breaches.",
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
    });
  }

  /**
   * Handle the check_email tool
   */
  private async handleCheckEmail(args: any) {
    if (!args.email || typeof args.email !== "string") {
      throw new McpError(
        ErrorCode.InvalidParams,
        "Email address is required"
      );
    }

    const params: Record<string, any> = {};

    if (args.include_unverified !== undefined) {
      params.includeUnverified = args.include_unverified;
    }

    if (args.truncate_response !== undefined) {
      params.truncateResponse = args.truncate_response;
    }

    const response = await this.axiosInstance.get(`/breachedaccount/${encodeURIComponent(args.email)}`, { params });

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

    let summary = `⚠️ This email address was found in ${breachCount} data breach${breachCount > 1 ? 'es' : ''}.\n\n`;

    if (args.truncate_response) {
      // If truncated, just list the breach names
      summary += "Breaches: " + breaches.map((breach: any) => breach.Name).join(", ");
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
      summary += "- If you used the same password elsewhere, change those too\n";
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
    };
  }

  /**
   * Handle the check_password tool
   * Uses the k-anonymity model to check passwords without sending the full password
   */
  private async handleCheckPassword(args: any) {
    if (!args.password || typeof args.password !== "string") {
      throw new McpError(
        ErrorCode.InvalidParams,
        "Password is required"
      );
    }

    // Hash the password with SHA-1
    const sha1Hash = crypto.createHash("sha1").update(args.password).digest("hex").toUpperCase();

    // Get the first 5 characters (prefix) and the rest (suffix)
    const prefix = sha1Hash.substring(0, 5);
    const suffix = sha1Hash.substring(5);

    // Query the API with just the prefix (k-anonymity)
    const response = await axios.get(`https://api.pwnedpasswords.com/range/${prefix}`);

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
      throw new McpError(
        ErrorCode.InvalidParams,
        "Breach name is required"
      );
    }

    const response = await this.axiosInstance.get(`/breach/${encodeURIComponent(args.breach_name)}`);

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
      details += "⚠️ Note: This breach has been flagged as potentially fabricated.\n\n";
    }

    if (breach.IsSensitive) {
      details += "⚠️ Note: This breach contains sensitive information.\n\n";
    }

    if (breach.IsRetired) {
      details += "ℹ️ Note: This breach has been retired from active display.\n\n";
    }

    if (breach.IsSpamList) {
      details += "ℹ️ Note: This breach is from a spam list.\n\n";
    }

    details += "**Recommendations:**\n";
    details += "- If you had an account on this service, change your password\n";
    details += "- If you used the same password elsewhere, change those too\n";
    details += "- Monitor your accounts for suspicious activity\n";
    details += "- Be cautious of phishing attempts that may use this leaked information";

    return {
      content: [
        {
          type: "text",
          text: details,
        },
      ],
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
            text: args && args.domain
              ? `No breaches found for domain: ${args.domain}`
              : "No breaches found in the system.",
          },
        ],
      };
    }

    const breaches = response.data;

    // Format the breach list for better readability
    let summary = args && args.domain
      ? `Found ${breaches.length} breaches for domain ${args.domain}:\n\n`
      : `Found ${breaches.length} breaches in the system:\n\n`;

    // Sort breaches by date (newest first)
    breaches.sort((a: any, b: any) => {
      return new Date(b.BreachDate).getTime() - new Date(a.BreachDate).getTime();
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
