export type JsonPrimitive = string | number | boolean | null;
export type JsonValue =
  | JsonPrimitive
  | JsonValue[]
  | { [key: string]: JsonValue };

export interface DeviceAuthRequest {
  device_code: string;
  user_code: string;
  verification_url: string;
  verification_url_complete: string;
  expires_in: number;
  interval: number;
}

export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: string;
  /** Absolute epoch-ms when the access token expires (computed on store). */
  expires_at?: number;
  /** Space-separated scopes granted for this session (echoed by the token endpoint). */
  scope?: string;
  /** Authorization details granted for this session (echoed by the token endpoint). */
  authorization_details?: JsonValue[];
}

export interface LineItem {
  name: string;
  url?: string;
  image_url?: string;
  description?: string;
  sku?: string;
  totals?: Total[];
  quantity?: number;
  unit_amount?: number;
  product_url?: string;
}

export interface Total {
  type: string;
  display_text: string;
  amount: number;
}

export interface BillingAddress {
  name: string;
  line1: string;
  line2?: string;
  city?: string;
  state?: string;
  postal_code?: string;
  country: string;
}

export interface Card {
  id: string;
  brand: string;
  exp_month: number;
  exp_year: number;
  number: string;
  cvc?: string;
  billing_address?: BillingAddress;
  valid_until?: string;
}

export type SpendRequestStatus =
  | 'created'
  | 'pending_approval'
  | 'expired'
  | 'approved'
  | 'denied'
  | 'succeeded'
  | 'failed'
  | 'canceled';

export type CredentialType = 'shared_payment_token' | 'card';

export interface ApprovalDetail {
  approved_at: number;
  approval_method: 'click' | 'programmatic' | 'voice';
  app_name: string;
  external_user_id: string;
  ip_address?: string;
  user_agent?: string;
  device_type?: 'mobile' | 'web';
  agent_log_id?: string;
  external_user_name?: string;
  external_session_id?: string;
  authentication_method?:
    | 'biometric_face'
    | 'biometric_fingerprint'
    | 'passkey';
}

export interface SharedPaymentToken {
  id: string;
  billing_address?: BillingAddress;
  valid_until?: string;
}

export interface RefundDetails {
  amount: number;
  currency: string;
  state: string;
  created: number;
}

export interface PaymentStatusDetails {
  outcome: 'success' | 'failure';
  code?: string | null;
  decline_code?: string | null;
  amount: number;
  currency: string;
  created?: number | null;
  refund_details?: RefundDetails | null;
}

export interface SpendRequest {
  id: string;
  merchant_name?: string;
  merchant_url?: string;
  context?: string;
  amount?: number;
  currency?: string;
  line_items: LineItem[];
  totals: Total[];
  payment_method?: string;
  payment_details: string;
  credential_type?: CredentialType;
  network_id?: string;
  card_brand?: string;
  card_last4?: string;
  status: SpendRequestStatus;
  approval_url?: string;
  card?: Card;
  shared_payment_token?: SharedPaymentToken;
  link_pay_token?: string;
  payment_status_details?: PaymentStatusDetails | null;
  link_transaction_id?: string;
  activity_url?: string;
  metadata?: Record<string, string>;
  created_at: string;
  updated_at: string;
}

export interface RequestApprovalResponse {
  id: string;
  approval_link: string;
}

export interface CardDetails {
  brand: string;
  last4: string;
  exp_month: number;
  exp_year: number;
}

export interface BankAccountDetails {
  last4: string;
  bank_name?: string;
}

export interface UserInfo {
  email?: string | null;
  name?: string | null;
  first_name?: string | null;
  last_name?: string | null;
  phone?: string | null;
}

export interface ProductCapability {
  eligible: boolean;
  ineligibility_reasons: string[];
}

export interface PaymentMethod {
  id: string;
  type: string;
  is_default: boolean;
  nickname?: string;
  card_details?: CardDetails;
  bank_account_details?: BankAccountDetails;
  capabilities?: Record<string, ProductCapability>;
}

export interface ShippingAddress {
  name: string | null;
  line_1: string | null;
  line_2: string | null;
  locality: string | null;
  dependent_locality: string | null;
  administrative_area: string | null;
  postal_code: string | null;
  sorting_code: string | null;
  country_code: string | null;
}

export interface ShippingAddressRecord {
  id: string;
  is_default: boolean;
  nickname: string | null;
  address: ShippingAddress | null;
}

export type TransactionOrigin = 'link' | 'external_connection';

export interface Transaction {
  id: string;
  source_id: string | null;
  amount: number;
  currency: string;
  created_date: string;
  description: string;
  origin: TransactionOrigin;
  category: string | null;
  status: string;
}

export interface TransactionsPage {
  data: Transaction[];
  has_more?: boolean;
  [key: string]: unknown;
}

export interface Source {
  id?: string | null;
  name?: string | null;
  type?: string | null;
  capabilities?: Record<string, unknown> | null;
  external_connection?: Record<string, unknown> | null;
  granted_actions?: string[] | null;
  bank_account?: Record<string, unknown> | null;
  card?: Record<string, unknown> | null;
  [key: string]: unknown;
}

export interface SourcesPage {
  data: Source[];
  has_more?: boolean;
  [key: string]: unknown;
}

export interface CashBalance {
  available: Record<string, number>;
}

export interface CreditBalance {
  used: Record<string, number>;
}

export interface Balance {
  source_id: string;
  type: 'cash' | 'credit';
  cash?: CashBalance | null;
  credit?: CreditBalance | null;
  current: number;
  currency: string;
  as_of: string;
  [key: string]: unknown;
}

export interface BalancesPage {
  data: Balance[];
  has_more?: boolean;
  [key: string]: unknown;
}

export interface WebBotAuthBlock {
  signature: string;
  signature_input: string;
  signature_agent: string;
  authority: string;
  expires_at: string;
}

/**
 * A single purchasable variant nested under a `UcpProduct`. Real catalog
 * search responses group results by product and put the fields needed to
 * check out (`profile_id`, `merchant_sku`, `price`) on each variant rather
 * than on the parent product.
 */
export interface UcpProductVariant {
  merchant_sku?: string;
  profile_id?: string;
  merchant_name?: string;
  price?: { amount?: number; currency?: string };
  availability?: { status?: string };
  title?: string;
  [key: string]: unknown;
}

/**
 * A product returned by UCP catalog search, mirroring the upstream
 * `CatalogSearchProduct` (real fields are `sku` and `title`, and every product
 * carries a `profile_id` used to create a checkout). The api.link.com contract
 * keeps the resource loose, so fields beyond these are passed through verbatim
 * via the index signature. `sku_id`/`name` are accepted as aliases.
 *
 * In practice, responses are grouped by product with the checkout-relevant
 * fields (`profile_id`, sku, price) nested under `variants` instead of on the
 * product itself — see `UcpProductVariant`.
 */
export interface UcpProduct {
  sku?: string;
  title?: string;
  profile_id?: string;
  merchant_name?: string;
  brand?: string;
  price?: number;
  sale_price?: number;
  currency?: string;
  availability?: string;
  product_category?: string;
  condition?: string;
  color?: string;
  size?: string;
  material?: string;
  gender?: string;
  review_count?: number;
  review_rating?: number;
  image_link?: string;
  link?: string;
  item_group_id?: string;
  item_group_title?: string;
  variants?: UcpProductVariant[];
  first_variant_price?: { amount?: number; currency?: string };
  /** Legacy/alias fields from the checkout PR's demo shape. */
  sku_id?: string;
  name?: string;
  [key: string]: unknown;
}

export interface UcpSearchResult {
  data: UcpProduct[];
  total_count?: number | null;
  has_more?: boolean | null;
  took_ms?: number | null;
  facets?: Record<string, unknown> | null;
  suggestions?: unknown;
  [key: string]: unknown;
}

/**
 * A UCP checkout session (curated view of the Delegated Checkout requested
 * session). `create` returns it in `requires_payment`; `complete` returns it in
 * a terminal state with `order_details`.
 */
export interface UcpCheckout {
  id: string;
  status?: string | null;
  currency?: string | null;
  amount_total?: number | null;
  amount_subtotal?: number | null;
  total_details?: Record<string, unknown> | null;
  line_item_details?: unknown;
  fulfillment_details?: Record<string, unknown> | null;
  order_details?: Record<string, unknown> | null;
  expires_at?: number | null;
  [key: string]: unknown;
}
