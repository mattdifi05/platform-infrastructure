\connect app_db

ALTER TABLE app_account.sessions
  ADD COLUMN IF NOT EXISTS device_type text NOT NULL DEFAULT 'unknown',
  ADD COLUMN IF NOT EXISTS device_vendor text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS device_model text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS browser_name text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS browser_version text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS engine_name text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS engine_version text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS os_name text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS os_version text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS user_agent text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS user_agent_hash text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS ip_version text NOT NULL DEFAULT 'unknown',
  ADD COLUMN IF NOT EXISTS region text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS timezone text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS asn text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS isp text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS network_org text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS network_type text NOT NULL DEFAULT 'unknown',
  ADD COLUMN IF NOT EXISTS effective_network_type text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS downlink_mbps numeric(9,3),
  ADD COLUMN IF NOT EXISTS rtt_ms integer,
  ADD COLUMN IF NOT EXISTS save_data boolean,
  ADD COLUMN IF NOT EXISTS screen_width integer,
  ADD COLUMN IF NOT EXISTS screen_height integer,
  ADD COLUMN IF NOT EXISTS screen_avail_width integer,
  ADD COLUMN IF NOT EXISTS screen_avail_height integer,
  ADD COLUMN IF NOT EXISTS viewport_width integer,
  ADD COLUMN IF NOT EXISTS viewport_height integer,
  ADD COLUMN IF NOT EXISTS device_pixel_ratio numeric(6,3),
  ADD COLUMN IF NOT EXISTS color_depth integer,
  ADD COLUMN IF NOT EXISTS pixel_depth integer,
  ADD COLUMN IF NOT EXISTS hardware_concurrency integer,
  ADD COLUMN IF NOT EXISTS device_memory_gb numeric(8,2),
  ADD COLUMN IF NOT EXISTS max_touch_points integer,
  ADD COLUMN IF NOT EXISTS cookies_enabled boolean,
  ADD COLUMN IF NOT EXISTS do_not_track text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS webdriver boolean,
  ADD COLUMN IF NOT EXISTS locale text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS languages text[] NOT NULL DEFAULT ARRAY[]::text[],
  ADD COLUMN IF NOT EXISTS platform text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS platform_version text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS architecture text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS bitness text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS client_hints_mobile boolean,
  ADD COLUMN IF NOT EXISTS color_scheme text NOT NULL DEFAULT 'unknown',
  ADD COLUMN IF NOT EXISTS reduced_motion boolean,
  ADD COLUMN IF NOT EXISTS forced_colors boolean;

ALTER TABLE app_account.sessions
  ALTER COLUMN downlink_mbps TYPE numeric(9,3);

UPDATE app_account.sessions
SET
  browser_name = coalesce(nullif(browser_name, ''), browser),
  ip_version = case
    when ip_address is null then 'unknown'
    when family(ip_address) = 4 then 'IPv4'
    when family(ip_address) = 6 then 'IPv6'
    else 'unknown'
  end
WHERE browser_name = ''
   OR ip_version = 'unknown';

ALTER TABLE app_account.sessions
  DROP CONSTRAINT IF EXISTS sessions_device_type_valid,
  ADD CONSTRAINT sessions_device_type_valid CHECK (device_type IN ('bot', 'desktop', 'mobile', 'tablet', 'unknown'));

ALTER TABLE app_account.sessions
  DROP CONSTRAINT IF EXISTS sessions_ip_version_valid,
  ADD CONSTRAINT sessions_ip_version_valid CHECK (ip_version IN ('IPv4', 'IPv6', 'unknown'));

ALTER TABLE app_account.sessions
  DROP CONSTRAINT IF EXISTS sessions_network_type_valid,
  ADD CONSTRAINT sessions_network_type_valid CHECK (network_type IN ('bluetooth', 'cellular', 'ethernet', 'mixed', 'none', 'other', 'unknown', 'wifi', 'wimax'));

ALTER TABLE app_account.sessions
  DROP CONSTRAINT IF EXISTS sessions_effective_network_type_valid,
  ADD CONSTRAINT sessions_effective_network_type_valid CHECK (effective_network_type IN ('', 'slow-2g', '2g', '3g', '4g', 'unknown'));

ALTER TABLE app_account.sessions
  DROP CONSTRAINT IF EXISTS sessions_color_scheme_valid,
  ADD CONSTRAINT sessions_color_scheme_valid CHECK (color_scheme IN ('dark', 'light', 'no-preference', 'unknown'));

ALTER TABLE app_account.sessions
  DROP CONSTRAINT IF EXISTS sessions_network_measurements_valid,
  ADD CONSTRAINT sessions_network_measurements_valid CHECK (
    (downlink_mbps IS NULL OR downlink_mbps >= 0)
    AND (rtt_ms IS NULL OR rtt_ms >= 0)
    AND (screen_width IS NULL OR screen_width >= 0)
    AND (screen_height IS NULL OR screen_height >= 0)
    AND (screen_avail_width IS NULL OR screen_avail_width >= 0)
    AND (screen_avail_height IS NULL OR screen_avail_height >= 0)
    AND (viewport_width IS NULL OR viewport_width >= 0)
    AND (viewport_height IS NULL OR viewport_height >= 0)
    AND (device_pixel_ratio IS NULL OR device_pixel_ratio >= 0)
    AND (color_depth IS NULL OR color_depth >= 0)
    AND (pixel_depth IS NULL OR pixel_depth >= 0)
    AND (hardware_concurrency IS NULL OR hardware_concurrency >= 0)
    AND (device_memory_gb IS NULL OR device_memory_gb >= 0)
    AND (max_touch_points IS NULL OR max_touch_points >= 0)
  );

COMMENT ON COLUMN app_account.sessions.metadata IS 'Flexible session telemetry such as client network API availability and source confidence.';
