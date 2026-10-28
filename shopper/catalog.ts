/** Synthetic demo merchant catalog (no real merchant, no real products). Prices in USD cents. */
export type Product = { sku: string; name: string; priceCents: number; tags: string[]; inStock: boolean };
export const DEMO_MERCHANT = { id: "harbor-supply", name: "Harbor Supply Co." } as const;
/** Settlement account reference the TPA USD pilot binds as the mandate recipient. */
export const DEMO_MERCHANT_ACCOUNT = "user:7001";
export const DEMO_MERCHANT_METAL_ADDRESS = "0x00000000000000000000000000000000000ba5e1";
export const TAX_BPS = 825; // 8.25%
export const SHIPPING = { standard: 599, express: 1499 } as const;

export const CATALOG: Product[] = [
  { sku: "COF-BEANS-1KG", name: "Dark roast coffee beans, 1 kg", priceCents: 2400, tags: ["coffee", "beans", "office", "kitchen"], inStock: true },
  { sku: "COF-GRINDER", name: "Burr coffee grinder", priceCents: 4900, tags: ["coffee", "grinder", "kitchen"], inStock: true },
  { sku: "COF-POUROVER", name: "Pour-over dripper kit", priceCents: 2900, tags: ["coffee", "brew", "kitchen", "office"], inStock: true },
  { sku: "COF-ESPRESSO", name: "Espresso machine", priceCents: 38900, tags: ["coffee", "espresso", "kitchen"], inStock: true },
  { sku: "MUG-SET-4", name: "Ceramic mug set of 4", priceCents: 2200, tags: ["mug", "coffee", "office", "kitchen"], inStock: true },
  { sku: "FILTER-100", name: "Paper filters, 100 pack", priceCents: 600, tags: ["coffee", "filter", "brew"], inStock: true },
  { sku: "TEA-SAMPLER", name: "Loose leaf tea sampler", priceCents: 1800, tags: ["tea", "office", "kitchen"], inStock: true },
  { sku: "KETTLE-GOOSE", name: "Gooseneck kettle", priceCents: 3900, tags: ["kettle", "coffee", "tea", "brew"], inStock: false },
  { sku: "WARRANTY-PLUS", name: "Extended protection plan", priceCents: 4999, tags: ["warranty"], inStock: true },
];

export const taxFor = (subtotalCents: number) => Math.round((subtotalCents * TAX_BPS) / 10_000);
