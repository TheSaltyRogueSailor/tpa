export type TpaAuthority = {
  enabled: boolean;
  valid: boolean;
  origin: string;
  rpID: string;
};

export type TpaAuthorityConfig = {
  enabled?: boolean;
  origin?: string;
  rpID?: string;
  localDevelopment?: boolean;
};

function exactOrigin(value: string | undefined): URL | null {
  if (!value || value.length > 255) return null;
  try {
    const parsed = new URL(value);
    if (parsed.origin !== value || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) return null;
    return parsed;
  } catch {
    return null;
  }
}

/**
 * Deployment configuration is explicit; it is never derived from Host,
 * X-Forwarded-Host, an HTTP request, or browser-controlled data.
 */
export function createTpaAuthority(config: TpaAuthorityConfig): TpaAuthority {
  const enabled = config.enabled === true;
  const parsed = exactOrigin(config.origin);
  const origin = parsed?.origin ?? "";
  const rpID = config.rpID ?? parsed?.hostname ?? "";
  const validRPID = !!parsed && rpID === parsed.hostname && /^[a-z0-9.-]{1,253}$/.test(rpID);
  const allowedProtocol = parsed?.protocol === "https:";
  const localhostAllowed = parsed?.hostname !== "localhost" || config.localDevelopment === true;
  return { enabled, valid: Boolean(allowedProtocol && localhostAllowed && validRPID), origin, rpID };
}

/** Environment helper intentionally fails closed when TPA_ORIGIN is absent. */
export function tpaAuthorityFromEnv(environment: NodeJS.ProcessEnv = process.env): TpaAuthority {
  return createTpaAuthority({
    enabled: environment.TPA_AUTHORIZATION_ENABLED === "true",
    origin: environment.TPA_ORIGIN,
    rpID: environment.TPA_RP_ID,
    localDevelopment: environment.NODE_ENV === "development",
  });
}

export type OriginHeaders = Record<string, string | string[] | undefined>;

function header(headers: OriginHeaders | undefined, name: string): string | undefined {
  const value = headers?.[name] ?? headers?.[name.toLowerCase()];
  return typeof value === "string" ? value : undefined;
}

/** Mutations require exact Origin. Read-only status may use authenticated same-origin Fetch Metadata. */
export function hasTpaRequestOrigin(headers: OriginHeaders | undefined, authority: TpaAuthority, readOnly = false): boolean {
  if (!authority.valid) return false;
  const origin = header(headers, "origin");
  if (origin !== undefined) return origin === authority.origin;
  return readOnly
    && header(headers, "x-tpa-origin") === authority.origin
    && header(headers, "sec-fetch-site") === "same-origin";
}
