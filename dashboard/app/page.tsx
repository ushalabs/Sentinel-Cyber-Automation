"use client";

import type { ReactNode } from "react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import ThemeToggle from "@/components/ThemeToggle";

type Detection = {
  id: number;
  prediction: string;
  attack: boolean;
  confidence: number;
  attack_probability: number;
  threshold: number;
  model: string;
  created_at: string;
};

type DashboardStats = {
  total_detections: number;
  attacks: number;
  benign: number;
  attack_rate: number;
  pending_review: number;
  critical_incidents: number;
};

type ActivityPoint = {
  timestamp: string;
  total: number;
  attacks: number;
  benign: number;
};

type LiveEvent = {
  event?: string;
  detection_id?: number;
  message?: string;
};

type SeverityPoint = {
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  count: number;
};

type TopPort = {
  port: number;
  count: number;
};

type TopSource = {
  source_ip: string;
  count: number;
};

type SystemStatus = {
  api: string;
  database: string;
  model: string;
  n8n: string;
  collector: string;
};

type AttentionItem = {
  id: number;
  prediction: string;
  confidence: number;
  attack_probability: number;
  source_ip: string | null;
  destination_ip: string | null;
  source_port: number | null;
  destination_port: number | null;
  transport_protocol: string | null;
  severity: string | null;
  analysis_status: string | null;
  review_status: string | null;
  attention_state: "ANALYZING" | "PENDING_REVIEW" | "ANALYSIS_FAILED";
  created_at: string;
};

type NormalizedActivityPoint = ActivityPoint & {
  label: string;
};

const SENTINEL_TIME_ZONE = "Asia/Karachi";

const activityHourKeyFormatter = new Intl.DateTimeFormat("en-GB", {
  timeZone: SENTINEL_TIME_ZONE,
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  hourCycle: "h23",
});

const activityLabelFormatter = new Intl.DateTimeFormat("en-GB", {
  timeZone: SENTINEL_TIME_ZONE,
  hour: "2-digit",
  minute: "2-digit",
  hourCycle: "h23",
});

export default function Home() {
  const router = useRouter();

  const [detections, setDetections] = useState<Detection[]>([]);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [activity, setActivity] = useState<ActivityPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [liveConnected, setLiveConnected] = useState(false);
  const [lastLiveEvent, setLastLiveEvent] = useState("");
  const [severity, setSeverity] = useState<SeverityPoint[]>([]);
  const [topPorts, setTopPorts] = useState<TopPort[]>([]);
  const [topSources, setTopSources] = useState<TopSource[]>([]);
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);

  const [attention, setAttention] = useState<AttentionItem[]>([]);

  const loadDashboard = useCallback(async () => {
    try {
      const [
        detectionsResponse,
        statsResponse,
        activityResponse,
        severityResponse,
        portsResponse,
        sourcesResponse,
        systemStatusResponse,
        attentionResponse,
      ] = await Promise.all([
        fetch("http://127.0.0.1:8000/detections"),
        fetch("http://127.0.0.1:8000/dashboard/stats"),
        fetch("http://127.0.0.1:8000/dashboard/activity?hours=24"),
        fetch("http://127.0.0.1:8000/dashboard/severity"),
        fetch("http://127.0.0.1:8000/dashboard/top-ports"),
        fetch("http://127.0.0.1:8000/dashboard/top-sources"),
        fetch("http://127.0.0.1:8000/system/status"),
        fetch("http://127.0.0.1:8000/dashboard/attention"),
      ]);

      if (!detectionsResponse.ok) {
        throw new Error("Failed to load detections");
      }

      if (!statsResponse.ok) {
        throw new Error("Failed to load dashboard statistics");
      }

      if (!activityResponse.ok) {
        throw new Error("Failed to load detection activity");
      }

      if (!severityResponse.ok) {
        throw new Error("Failed to load severity analytics");
      }

      if (!portsResponse.ok) {
        throw new Error("Failed to load targeted ports");
      }

      if (!sourcesResponse.ok) {
        throw new Error("Failed to load source IP analytics");
      }

      if (!systemStatusResponse.ok) {
        throw new Error("Failed to load system status");
      }

      if (!attentionResponse.ok) {
        throw new Error("Failed to load analyst queue");
      }

      const detectionsData: Detection[] =
        await detectionsResponse.json();

      const statsData: DashboardStats =
        await statsResponse.json();

      const activityData: ActivityPoint[] =
        await activityResponse.json();

      const severityData: SeverityPoint[] =
        await severityResponse.json();

      const portsData: TopPort[] =
        await portsResponse.json();

      const sourcesData: TopSource[] =
        await sourcesResponse.json();

      const systemStatusData: SystemStatus =
        await systemStatusResponse.json();

      const attentionData: AttentionItem[] =
        await attentionResponse.json();

      setDetections(detectionsData);
      setStats(statsData);
      setActivity(activityData);
      setSeverity(severityData);
      setTopPorts(portsData);
      setTopSources(sourcesData);
      setSystemStatus(systemStatusData);
      setAttention(attentionData);
      setError("");
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unknown error"
      );
    } finally {
      setLoading(false);
    }
  }, []);

  const dismissFromQueue = useCallback(
    async (detectionId: number) => {
      try {
        const response = await fetch(
          `http://127.0.0.1:8000/detections/${detectionId}/dismiss-from-queue`,
          {
            method: "POST",
          }
        );

        if (!response.ok) {
          const body = await response.text();

          throw new Error(
            body ||
              "Failed to dismiss incident from Analyst Queue"
          );
        }

        // Remove immediately from the UI.
        setAttention((current) =>
          current.filter(
            (item) => item.id !== detectionId
          )
        );
      } catch (err) {
        window.alert(
          err instanceof Error
            ? err.message
            : "Failed to dismiss incident from Analyst Queue"
        );
      }
    },
    []
  );

  useEffect(() => {
    loadDashboard();
  }, [loadDashboard]);

  useEffect(() => {
    let cancelled = false;

    const loadSystemHealth = async () => {
      try {
        const response = await fetch(
          "http://127.0.0.1:8000/system/status",
          { cache: "no-store" }
        );

        if (!response.ok) {
          return;
        }

        const data: SystemStatus = await response.json();

        if (!cancelled) {
          setSystemStatus(data);
        }
      } catch {
        // Keep the last known status if the health endpoint is temporarily unreachable.
      }
    };

    loadSystemHealth();

    const interval = window.setInterval(
      loadSystemHealth,
      5000
    );

    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    let socket: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let active = true;

    const connect = () => {
      if (!active) return;

      socket = new WebSocket(
        "ws://127.0.0.1:8000/ws/events"
      );

      socket.onopen = () => {
        setLiveConnected(true);
      };

      socket.onmessage = (message) => {
        try {
          const event: LiveEvent =
            JSON.parse(message.data);

          setLastLiveEvent(
            event.event ?? "LIVE_EVENT"
          );

          const refreshEvents = new Set([
            "DETECTION_CREATED",
            "THREAT_INTELLIGENCE_UPDATED",
            "ANALYSIS_COMPLETED",
            "REVIEW_UPDATED",
            "RESPONSE_UPDATED",
            "QUEUE_DISMISSED",
          ]);

          if (
            event.event &&
            refreshEvents.has(event.event)
          ) {
            loadDashboard();
          }
        } catch {
          setLastLiveEvent("LIVE_EVENT");
        }
      };

      socket.onerror = () => {
        socket?.close();
      };

      socket.onclose = () => {
        setLiveConnected(false);

        if (active) {
          reconnectTimer = setTimeout(
            connect,
            2000
          );
        }
      };
    };

    connect();

    return () => {
      active = false;

      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
      }

      socket?.close();
    };
  }, [loadDashboard]);

  const normalizedActivity = useMemo(
    () => buildLast24Hours(activity),
    [activity]
  );

  return (
    <main className="min-h-screen bg-zinc-50 text-zinc-950 transition-colors dark:bg-zinc-950 dark:text-white">
      <div className="mx-auto max-w-[1600px] px-6 py-10">
        <header className="mb-10 flex items-start justify-between gap-6">
          <div>
            <p className="mb-2 text-sm font-semibold uppercase tracking-[0.35em] text-emerald-500 dark:text-emerald-400">
              Sentinel
            </p>

            <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">
              Security Operations Dashboard
            </h1>

            <p className="mt-3 max-w-2xl text-zinc-600 dark:text-zinc-400">
              Network intrusion detection, incident analysis
              and human-supervised response.
            </p>
          </div>

          <ThemeToggle />
        </header>

        <section className="mb-5 xl:hidden">
          <AnalystQueuePanel
            attention={attention}
            onDismiss={dismissFromQueue}
          />
        </section>

        <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_340px] xl:items-start">
          <div className="min-w-0">
        <section className="mb-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <StatCard
            title="Total Detections"
            value={
              stats
                ? String(stats.total_detections)
                : "—"
            }
            description="All recorded network events"
          />

          <StatCard
            title="Attacks"
            value={
              stats
                ? String(stats.attacks)
                : "—"
            }
            description="Flows classified as ATTACK"
          />

          <StatCard
            title="Benign"
            value={
              stats
                ? String(stats.benign)
                : "—"
            }
            description="Flows classified as BENIGN"
          />

          <StatCard
            title="Attack Rate"
            value={
              stats
                ? `${stats.attack_rate.toFixed(1)}%`
                : "—"
            }
            description="Attack share across all records"
          />

          <StatCard
            title="Pending Review"
            value={
              stats
                ? String(stats.pending_review)
                : "—"
            }
            description="Incidents waiting for analyst action"
          />

          <StatCard
            title="Critical Incidents"
            value={
              stats
                ? String(stats.critical_incidents)
                : "—"
            }
            description="Incidents currently rated CRITICAL"
          />
        </section>

        <section className="mb-8 rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm transition-colors dark:border-zinc-800 dark:bg-zinc-900 dark:shadow-none">
          <div className="mb-6 flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.28em] text-emerald-600 dark:text-emerald-400">
                Live Analytics
              </p>

              <h2 className="mt-2 text-xl font-semibold">
                Detection Activity
              </h2>

              <p className="mt-1 text-sm text-zinc-500 dark:text-zinc-400">
                Hourly ATTACK and BENIGN classifications
                during the last 24 hours.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-4 text-xs font-medium text-zinc-500 dark:text-zinc-400">
              <LegendDot className="bg-red-500" label="Attack" />
              <LegendDot className="bg-emerald-500" label="Benign" />
            </div>
          </div>

          <DetectionActivityChart data={normalizedActivity} />
        </section>

        <section className="mb-8 grid gap-5 lg:grid-cols-3">
          <AnalyticsCard
            title="Severity Distribution"
            subtitle="AI-analyzed ATTACK incidents"
          >
            <div className="space-y-4">
              {severity.map((item) => (
                <SeverityRow
                  key={item.severity}
                  severity={item.severity}
                  count={item.count}
                  max={Math.max(1, ...severity.map((entry) => entry.count))}
                />
              ))}
            </div>
          </AnalyticsCard>

          <AnalyticsCard
            title="Top Targeted Ports"
            subtitle="Destination ports among ATTACK detections"
          >
            <RankedList
              items={topPorts.map((item) => ({
                label: `Port ${item.port}`,
                value: item.count,
              }))}
              emptyText="No targeted ports available."
            />
          </AnalyticsCard>

          <AnalyticsCard
            title="Top Source IPs"
            subtitle="Source addresses among ATTACK detections"
          >
            <RankedList
              items={topSources.map((item) => ({
                label: item.source_ip,
                value: item.count,
              }))}
              emptyText="No source IPs available."
              monospace
            />
          </AnalyticsCard>
        </section>

        <section className="mb-8 rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm transition-colors dark:border-zinc-800 dark:bg-zinc-900 dark:shadow-none">
          <div className="mb-5 flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.28em] text-emerald-600 dark:text-emerald-400">
                Platform Health
              </p>

              <h2 className="mt-2 text-xl font-semibold">
                System Status
              </h2>

              <p className="mt-1 text-sm text-zinc-500 dark:text-zinc-400">
                Current availability of Sentinel core services.
              </p>
            </div>

            <div className="text-xs text-zinc-500 dark:text-zinc-400">
              Updates with live dashboard refreshes
            </div>
          </div>

          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            <HealthItem label="FastAPI" status={systemStatus?.api ?? "UNKNOWN"} />
            <HealthItem label="PostgreSQL" status={systemStatus?.database ?? "UNKNOWN"} />
            <HealthItem label="XGBoost" status={systemStatus?.model ?? "UNKNOWN"} />
            <HealthItem label="n8n" status={systemStatus?.n8n ?? "UNKNOWN"} />
            <HealthItem label="Collector" status={systemStatus?.collector ?? "UNKNOWN"} />
          </div>
        </section>

        <section className="overflow-hidden rounded-2xl border border-zinc-200 bg-white shadow-sm transition-colors dark:border-zinc-800 dark:bg-zinc-900 dark:shadow-none">
          <div className="flex items-center justify-between border-b border-zinc-200 px-6 py-5 dark:border-zinc-800">
            <div>
              <h2 className="text-xl font-semibold">
                Recent Detections
              </h2>

              <p className="mt-1 text-sm text-zinc-500 dark:text-zinc-400">
                Select a detection to inspect the complete incident.
              </p>

              {lastLiveEvent && (
                <p className="mt-2 text-xs text-zinc-400 dark:text-zinc-500">
                  Last live event: {lastLiveEvent}
                </p>
              )}
            </div>

            <div
              className={`hidden rounded-full px-3 py-1 text-xs font-semibold sm:block ${
                liveConnected
                  ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                  : "bg-amber-500/10 text-amber-600 dark:text-amber-400"
              }`}
            >
              {liveConnected
                ? "LIVE STREAM CONNECTED"
                : "LIVE STREAM RECONNECTING"}
            </div>
          </div>

          {loading && (
            <div className="p-8 text-sm text-zinc-500 dark:text-zinc-400">
              Loading Sentinel dashboard...
            </div>
          )}

          {error && (
            <div className="p-8 text-sm text-red-500">
              {error}
            </div>
          )}

          {!loading &&
            !error &&
            detections.length === 0 && (
              <div className="p-8 text-sm text-zinc-500 dark:text-zinc-400">
                No detections are currently available.
              </div>
            )}

          {!loading &&
            !error &&
            detections.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[760px] text-left">
                  <thead className="bg-zinc-50 text-xs uppercase tracking-wider text-zinc-500 dark:bg-zinc-950/50 dark:text-zinc-400">
                    <tr>
                      <th className="px-6 py-4">ID</th>
                      <th className="px-6 py-4">
                        Prediction
                      </th>
                      <th className="px-6 py-4">
                        Confidence
                      </th>
                      <th className="px-6 py-4">
                        Model
                      </th>
                      <th className="px-6 py-4">
                        Created
                      </th>
                      <th className="px-6 py-4 text-right">
                        Incident
                      </th>
                    </tr>
                  </thead>

                  <tbody>
                    {detections.map(
                      (detection) => (
                        <tr
                          key={detection.id}
                          onClick={() =>
                            router.push(
                              `/incidents/${detection.id}`
                            )
                          }
                          className="group cursor-pointer border-t border-zinc-200 transition hover:bg-zinc-50 dark:border-zinc-800 dark:hover:bg-zinc-800/50"
                        >
                          <td className="px-6 py-4 font-mono text-sm font-semibold">
                            #{detection.id}
                          </td>

                          <td className="px-6 py-4">
                            <PredictionBadge
                              attack={
                                detection.attack
                              }
                              prediction={
                                detection.prediction
                              }
                            />
                          </td>

                          <td className="px-6 py-4 font-medium">
                            {(
                              detection.confidence *
                              100
                            ).toFixed(2)}
                            %
                          </td>

                          <td className="px-6 py-4 text-zinc-700 dark:text-zinc-300">
                            {detection.model}
                          </td>

                          <td className="px-6 py-4 text-zinc-500 dark:text-zinc-400">
                            {new Date(
                              detection.created_at
                            ).toLocaleString()}
                          </td>

                          <td className="px-6 py-4 text-right text-zinc-400 transition group-hover:text-emerald-500">
                            →
                          </td>
                        </tr>
                      )
                    )}
                  </tbody>
                </table>
              </div>
            )}
        </section>
          </div>

          <aside
            className="hidden xl:sticky xl:top-6 xl:block xl:self-start"
            aria-label="Analyst queue"
          >
            <AnalystQueuePanel
            attention={attention}
            onDismiss={dismissFromQueue}
          />
          </aside>
        </div>
      </div>
    </main>
  );
}

function buildLast24Hours(
  activity: ActivityPoint[]
): NormalizedActivityPoint[] {
  const byHour = new Map<
    string,
    ActivityPoint
  >();

  for (const point of activity) {
    const date = new Date(point.timestamp);

    byHour.set(hourKey(date), point);
  }

  const now = new Date();
  now.setMinutes(0, 0, 0);

  const result: NormalizedActivityPoint[] = [];

  for (let index = 23; index >= 0; index--) {
    const date = new Date(
      now.getTime() - index * 60 * 60 * 1000
    );

    const existing = byHour.get(hourKey(date));

    result.push({
      timestamp: date.toISOString(),
      total: existing?.total ?? 0,
      attacks: existing?.attacks ?? 0,
      benign: existing?.benign ?? 0,
      label: activityLabelFormatter.format(date),
    });
  }

  return result;
}

function hourKey(date: Date) {
  const parts = activityHourKeyFormatter.formatToParts(date);

  const values = Object.fromEntries(
    parts
      .filter((part) =>
        ["year", "month", "day", "hour"].includes(part.type)
      )
      .map((part) => [part.type, part.value])
  );

  return `${values.year}-${values.month}-${values.day}-${values.hour}`;
}

function DetectionActivityChart({
  data,
}: {
  data: NormalizedActivityPoint[];
}) {
  const width = 1000;
  const height = 300;

  const padding = {
    top: 24,
    right: 22,
    bottom: 44,
    left: 42,
  };

  const plotWidth =
    width - padding.left - padding.right;

  const plotHeight =
    height - padding.top - padding.bottom;

  const maxValue = Math.max(
    1,
    ...data.map((point) => point.total)
  );

  const yMax = Math.max(
    4,
    Math.ceil(maxValue / 4) * 4
  );

  const y = (value: number) =>
    padding.top +
    plotHeight -
    (value / yMax) * plotHeight;

  const bucketWidth =
    plotWidth / Math.max(data.length, 1);

  const barWidth = Math.min(
    24,
    bucketWidth * 0.62
  );

  const xCenter = (index: number) =>
    padding.left +
    bucketWidth * index +
    bucketWidth / 2;

  const yTicks = [0, 1, 2, 3, 4].map(
    (index) => (yMax / 4) * index
  );

  const xTickIndexes = [
    0,
    4,
    8,
    12,
    16,
    20,
    23,
  ];

  return (
    <div className="w-full overflow-x-auto">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="min-w-[760px] w-full"
        role="img"
        aria-label="Hourly attack and benign detections for the last 24 hours"
      >
        {yTicks.map((tick) => {
          const tickY = y(tick);

          return (
            <g key={tick}>
              <line
                x1={padding.left}
                y1={tickY}
                x2={width - padding.right}
                y2={tickY}
                className="stroke-zinc-200 dark:stroke-zinc-800"
                strokeWidth="1"
              />

              <text
                x={padding.left - 12}
                y={tickY + 4}
                textAnchor="end"
                className="fill-zinc-400 text-[11px] dark:fill-zinc-500"
              >
                {Math.round(tick)}
              </text>
            </g>
          );
        })}

        {data.map((point, index) => {
          const center = xCenter(index);
          const baselineY = y(0);
          const attackTopY = y(point.attacks);
          const totalTopY = y(point.total);

          const attackHeight =
            baselineY - attackTopY;

          const benignHeight =
            attackTopY - totalTopY;

          return (
            <g key={point.timestamp}>
              <title>
                {`${point.label} — Attack: ${point.attacks}, Benign: ${point.benign}, Total: ${point.total}`}
              </title>

              {point.attacks > 0 && (
                <rect
                  x={center - barWidth / 2}
                  y={attackTopY}
                  width={barWidth}
                  height={attackHeight}
                  rx="4"
                  className="fill-red-500"
                />
              )}

              {point.benign > 0 && (
                <rect
                  x={center - barWidth / 2}
                  y={totalTopY}
                  width={barWidth}
                  height={benignHeight}
                  rx="4"
                  className="fill-emerald-500"
                />
              )}

              {point.total > 0 && (
                <text
                  x={center}
                  y={totalTopY - 7}
                  textAnchor="middle"
                  className="fill-zinc-600 text-[11px] font-semibold dark:fill-zinc-300"
                >
                  {point.total}
                </text>
              )}
            </g>
          );
        })}

        {xTickIndexes.map((index) => (
          <text
            key={index}
            x={xCenter(index)}
            y={height - 12}
            textAnchor="middle"
            className="fill-zinc-400 text-[11px] dark:fill-zinc-500"
          >
            {data[index]?.label ?? ""}
          </text>
        ))}
      </svg>
    </div>
  );
}

function LegendDot({
  className,
  label,
}: {
  className: string;
  label: string;
}) {
  return (
    <span className="inline-flex items-center gap-2">
      <span
        className={`h-2.5 w-2.5 rounded-full ${className}`}
      />
      {label}
    </span>
  );
}

function AnalystQueuePanel({
  attention,
  onDismiss,
}: {
  attention: AttentionItem[];
  onDismiss: (detectionId: number) => void;
}) {
  return (
    <div className="overflow-hidden rounded-2xl border border-red-500/25 bg-white shadow-xl shadow-black/5 dark:border-red-500/25 dark:bg-zinc-900 dark:shadow-black/30">
      <div className="border-b border-zinc-200 px-5 py-5 dark:border-zinc-800">
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <span className="relative flex h-2.5 w-2.5">
                {attention.length > 0 && (
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-500 opacity-60" />
                )}

                <span
                  className={`relative inline-flex h-2.5 w-2.5 rounded-full ${
                    attention.length > 0
                      ? "bg-red-500"
                      : "bg-emerald-500"
                  }`}
                />
              </span>

              <p className="text-xs font-semibold uppercase tracking-[0.24em] text-red-600 dark:text-red-400">
                Analyst Queue
              </p>
            </div>

            <h2 className="mt-2 text-xl font-semibold">
              Needs Attention
            </h2>

            <p className="mt-1 text-xs leading-5 text-zinc-500 dark:text-zinc-400">
              ATTACK detections stay pinned here until reviewed or dismissed.
            </p>
          </div>

          <span className="rounded-full bg-red-500/10 px-2.5 py-1 text-xs font-bold text-red-700 dark:bg-red-500/15 dark:text-red-400">
            {attention.length}
          </span>
        </div>
      </div>

      <div className="max-h-[calc(100vh-3rem)] space-y-3 overflow-y-auto p-4">
        {attention.length === 0 ? (
          <div className="rounded-xl border border-dashed border-zinc-300 px-4 py-8 text-center dark:border-zinc-700">
            <div className="text-sm font-semibold">
              Queue clear
            </div>

            <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
              No ATTACK currently requires analyst attention.
            </p>
          </div>
        ) : (
          attention.map((item) => (
            <AttentionCard
              key={item.id}
              item={item}
              onDismiss={onDismiss}
            />
          ))
        )}
      </div>
    </div>
  );
}

function AttentionCard({
  item,
  onDismiss,
}: {
  item: AttentionItem;
  onDismiss: (detectionId: number) => void;
}) {
  const stateLabel =
    item.attention_state === "PENDING_REVIEW"
      ? "PENDING REVIEW"
      : item.attention_state === "ANALYSIS_FAILED"
        ? "ANALYSIS FAILED"
        : "ANALYZING";

  const stateClass =
    item.attention_state === "PENDING_REVIEW"
      ? "bg-amber-500/10 text-amber-700 dark:bg-amber-500/15 dark:text-amber-400"
      : item.attention_state === "ANALYSIS_FAILED"
        ? "bg-red-500/10 text-red-700 dark:bg-red-500/15 dark:text-red-400"
        : "bg-blue-500/10 text-blue-700 dark:bg-blue-500/15 dark:text-blue-400";

  const severityClass =
    item.severity === "CRITICAL"
      ? "bg-red-500/10 text-red-700 dark:bg-red-500/15 dark:text-red-400"
      : item.severity === "HIGH"
        ? "bg-orange-500/10 text-orange-700 dark:bg-orange-500/15 dark:text-orange-400"
        : item.severity === "MEDIUM"
          ? "bg-yellow-500/10 text-yellow-700 dark:bg-yellow-500/15 dark:text-yellow-400"
          : "bg-emerald-500/10 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-400";

  return (
    <div className="rounded-xl border border-zinc-200 bg-zinc-50 p-4 transition dark:border-zinc-800 dark:bg-zinc-950">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-sm font-bold">
            Incident #{item.id}
          </div>

          <div className="mt-1 font-mono text-xs text-zinc-500 dark:text-zinc-400">
            {item.source_ip ?? "Unknown source"}
            {item.source_port != null
              ? `:${item.source_port}`
              : ""}
          </div>
        </div>

        <span className="rounded-full bg-red-500/10 px-2.5 py-1 text-[11px] font-bold text-red-700 dark:bg-red-500/15 dark:text-red-400">
          ATTACK
        </span>
      </div>

      <div className="mt-4 flex flex-wrap gap-2">
        <span
          className={`rounded-full px-2.5 py-1 text-[11px] font-semibold ${stateClass}`}
        >
          {stateLabel}
        </span>

        {item.severity && (
          <span
            className={`rounded-full px-2.5 py-1 text-[11px] font-semibold ${severityClass}`}
          >
            {item.severity}
          </span>
        )}
      </div>

      <div className="mt-4 grid grid-cols-2 gap-3 text-xs">
        <div>
          <div className="text-zinc-500 dark:text-zinc-500">
            Confidence
          </div>

          <div className="mt-1 font-semibold">
            {(item.confidence * 100).toFixed(2)}%
          </div>
        </div>

        <div>
          <div className="text-zinc-500 dark:text-zinc-500">
            Protocol
          </div>

          <div className="mt-1 font-semibold">
            {item.transport_protocol ?? "—"}
          </div>
        </div>
      </div>

      <div className="mt-4 grid grid-cols-2 gap-2 border-t border-zinc-200 pt-3 dark:border-zinc-800">
        <a
          href={`/incidents/${item.id}`}
          className="flex items-center justify-center gap-2 rounded-lg bg-zinc-200 px-3 py-2 text-xs font-semibold text-zinc-800 transition hover:bg-zinc-300 dark:bg-zinc-800 dark:text-zinc-100 dark:hover:bg-zinc-700"
        >
          View
          <span aria-hidden="true">→</span>
        </a>

        <button
          type="button"
          onClick={() => onDismiss(item.id)}
          className="rounded-lg border border-red-500/30 px-3 py-2 text-xs font-semibold text-red-600 transition hover:bg-red-500/10 dark:text-red-400"
          title="Remove from Analyst Queue without deleting incident history"
        >
          Dismiss
        </button>
      </div>
    </div>
  );
}

function HealthItem({
  label,
  status,
}: {
  label: string;
  status: string;
}) {
  const healthy =
    status === "ONLINE" ||
    status === "LOADED" ||
    status === "RUNNING";
  const waiting = status === "NOT_STARTED" || status === "UNKNOWN";

  const badgeClass = healthy
    ? "bg-emerald-500/10 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-400"
    : waiting
      ? "bg-amber-500/10 text-amber-700 dark:bg-amber-500/15 dark:text-amber-400"
      : "bg-red-500/10 text-red-700 dark:bg-red-500/15 dark:text-red-400";

  const dotClass = healthy
    ? "bg-emerald-500"
    : waiting
      ? "bg-amber-500"
      : "bg-red-500";

  return (
    <div className="rounded-xl border border-zinc-200 bg-zinc-50 p-4 dark:border-zinc-800 dark:bg-zinc-950">
      <div className="flex items-center justify-between gap-3">
        <span className="text-sm font-semibold">{label}</span>
        <span className={`h-2.5 w-2.5 rounded-full ${dotClass}`} />
      </div>

      <div className={`mt-3 inline-flex rounded-full px-2.5 py-1 text-xs font-semibold ${badgeClass}`}>
        {status}
      </div>
    </div>
  );
}

function AnalyticsCard({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle: string;
  children: ReactNode;
}) {
  return (
    <div className="rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm transition-colors dark:border-zinc-800 dark:bg-zinc-900 dark:shadow-none">
      <h3 className="text-lg font-semibold">{title}</h3>
      <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
        {subtitle}
      </p>

      <div className="mt-6">{children}</div>
    </div>
  );
}

function SeverityRow({
  severity,
  count,
  max,
}: {
  severity: SeverityPoint["severity"];
  count: number;
  max: number;
}) {
  const width =
    count === 0 ? 0 : Math.max(8, (count / max) * 100);

  const barClasses: Record<SeverityPoint["severity"], string> = {
    LOW: "bg-emerald-500",
    MEDIUM: "bg-yellow-500",
    HIGH: "bg-orange-500",
    CRITICAL: "bg-red-500",
  };

  return (
    <div>
      <div className="mb-2 flex items-center justify-between gap-4">
        <span className="text-sm font-medium">{severity}</span>
        <span className="text-sm font-semibold text-zinc-600 dark:text-zinc-300">
          {count}
        </span>
      </div>

      <div className="h-2.5 overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800">
        <div
          className={`h-full rounded-full transition-all ${barClasses[severity]}`}
          style={{ width: `${width}%` }}
        />
      </div>
    </div>
  );
}

function RankedList({
  items,
  emptyText,
  monospace = false,
}: {
  items: { label: string; value: number }[];
  emptyText: string;
  monospace?: boolean;
}) {
  if (items.length === 0) {
    return (
      <p className="text-sm text-zinc-500 dark:text-zinc-400">
        {emptyText}
      </p>
    );
  }

  return (
    <div className="space-y-3">
      {items.map((item, index) => (
        <div
          key={`${item.label}-${index}`}
          className="flex items-center justify-between gap-4 rounded-xl border border-zinc-200 bg-zinc-50 px-4 py-3 dark:border-zinc-800 dark:bg-zinc-950"
        >
          <div className="flex min-w-0 items-center gap-3">
            <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-zinc-200 text-xs font-bold text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
              {index + 1}
            </span>

            <span
              className={`truncate text-sm font-medium ${
                monospace ? "font-mono" : ""
              }`}
            >
              {item.label}
            </span>
          </div>

          <span className="shrink-0 rounded-full bg-zinc-200 px-2.5 py-1 text-xs font-semibold text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
            {item.value}
          </span>
        </div>
      ))}
    </div>
  );
}

function StatCard({
  title,
  value,
  description,
}: {
  title: string;
  value: string;
  description: string;
}) {
  return (
    <div className="rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm transition-colors dark:border-zinc-800 dark:bg-zinc-900 dark:shadow-none">
      <p className="text-sm font-medium text-zinc-500 dark:text-zinc-400">
        {title}
      </p>

      <p className="mt-2 text-3xl font-bold tracking-tight">
        {value}
      </p>

      <p className="mt-2 text-xs text-zinc-500 dark:text-zinc-500">
        {description}
      </p>
    </div>
  );
}

function PredictionBadge({
  prediction,
  attack,
}: {
  prediction: string;
  attack: boolean;
}) {
  return (
    <span
      className={`inline-flex rounded-full px-3 py-1 text-xs font-semibold ${
        attack
          ? "bg-red-500/10 text-red-600 dark:bg-red-500/15 dark:text-red-400"
          : "bg-emerald-500/10 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-400"
      }`}
    >
      {prediction}
    </span>
  );
}
