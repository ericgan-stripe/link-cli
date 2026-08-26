import { z } from 'incur';

const ISO_DATE_REGEX = /^\d{4}-\d{2}-\d{2}$/;

export const listOptions = z.object({
  limit: z.coerce
    .number()
    .int()
    .positive()
    .max(100)
    .optional()
    .describe('Maximum number of transactions to return (1-100).'),
  startingAfter: z
    .string()
    .optional()
    .describe('Cursor: return transactions after this transaction ID.'),
  endingBefore: z
    .string()
    .optional()
    .describe('Cursor: return transactions before this transaction ID.'),
  startDate: z
    .string()
    .regex(ISO_DATE_REGEX, 'Date must be in YYYY-MM-DD format.')
    .optional()
    .describe('Only include transactions on or after this YYYY-MM-DD date.'),
  endDate: z
    .string()
    .regex(ISO_DATE_REGEX, 'Date must be in YYYY-MM-DD format.')
    .optional()
    .describe('Only include transactions on or before this YYYY-MM-DD date.'),
  category: z.string().optional().describe('Filter by transaction category.'),
  origin: z
    .enum(['link', 'external_connection'])
    .optional()
    .describe('Filter by transaction origin: link or external_connection.'),
  source: z
    .array(z.string())
    .default([])
    .describe('Filter by source ID. Repeat to include multiple sources.'),
});

export const updateOptions = z.object({
  category: z
    .string()
    .optional()
    .describe(
      'New category for the transaction. Must be a subcategory, not a category group — e.g. groceries, restaurants, rent, flights, coffee, electronics. Group-level values like "shopping" are rejected by the server. At least one of --category or --description is required. Empty strings are treated as absent and cannot clear the field.',
    ),
  description: z
    .string()
    .optional()
    .describe(
      'New description for the transaction. Replaces the existing description. At least one of --category or --description is required. Empty strings are treated as absent and cannot clear the field. Omitted fields are preserved.',
    ),
});
