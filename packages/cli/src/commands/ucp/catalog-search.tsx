import type {
  IUcpResource,
  SearchUcpCatalogParams,
  UcpSearchResult,
} from '@stripe/link-sdk';
import { Box, Text, useApp } from 'ink';
import Spinner from 'ink-spinner';
import type React from 'react';
import { useCallback } from 'react';
import { useAsyncAction } from '../../hooks/use-async-action';

interface CatalogSearchProps {
  repository: IUcpResource;
  params: SearchUcpCatalogParams;
  onComplete: (result: UcpSearchResult | null) => void;
}

function formatPrice(price?: number, currency?: string): string {
  if (price == null) return '';
  return `$${(price / 100).toFixed(2)} ${(currency ?? 'usd').toUpperCase()}`;
}

export const CatalogSearch: React.FC<CatalogSearchProps> = ({
  repository,
  params,
  onComplete,
}) => {
  const { exit } = useApp();
  const action = useCallback(
    () => repository.searchCatalog(params),
    [repository, params],
  );
  const wrappedOnComplete = useCallback(
    (result: UcpSearchResult | null) => {
      onComplete(result);
      exit();
    },
    [onComplete, exit],
  );
  const { status, data, error } = useAsyncAction(action, wrappedOnComplete);

  if (status === 'loading') {
    return (
      <Box>
        <Text color="cyan">
          <Spinner type="dots" /> Searching catalog...
        </Text>
      </Box>
    );
  }

  if (status === 'error') {
    return (
      <Box flexDirection="column">
        <Text color="red">✗ Catalog search failed</Text>
        <Text color="red">{error}</Text>
      </Box>
    );
  }

  const products = data?.data ?? [];
  if (products.length === 0) {
    return (
      <Box>
        <Text dimColor>No products found</Text>
      </Box>
    );
  }

  return (
    <Box flexDirection="column">
      <Text bold>
        Catalog results{' '}
        <Text dimColor>
          ({data?.total_count ?? products.length}
          {data?.has_more ? '+' : ''})
        </Text>
      </Text>
      <Box flexDirection="column" marginTop={1}>
        {products.map((product, index) => {
          const sku = product.sku ?? product.sku_id;
          const title = product.title ?? product.name;
          const price = formatPrice(
            product.sale_price ?? product.price,
            product.currency,
          );
          return (
            <Box key={sku ?? String(index)} flexDirection="column" paddingX={2}>
              <Text>
                <Text dimColor>{sku ?? '—'}</Text>
                {title ? `  ${title}` : ''}
                {product.brand ? `  ${product.brand}` : ''}
                {price ? `  ${price}` : ''}
                {product.availability ? `  (${product.availability})` : ''}
              </Text>
              {product.profile_id ? (
                <Text dimColor>
                  {'  '}network id: {product.profile_id}
                  {product.merchant_name ? `  (${product.merchant_name})` : ''}
                </Text>
              ) : null}
            </Box>
          );
        })}
      </Box>
      <Box marginTop={1}>
        <Text dimColor>
          Create a checkout with a network id and SKUs:{' '}
          <Text color="cyan">ucp checkout create --network-id ...</Text>
        </Text>
      </Box>
    </Box>
  );
};
