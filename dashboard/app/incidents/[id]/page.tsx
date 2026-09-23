"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import ThemeToggle from "@/components/ThemeToggle";

type IncidentAnalysis = {
  severity?: string;
  severity_reason?: string;
  summary?: string;
  likely_activity?: string;
  reasoning?: string[];
  risk_factors?: string[];
  recommended_actions?: string[];
  analyst_note?: string;
};

type ThreatIntelligence = {
  abuse_confidence_score?: number;
  is_whitelisted?: boolean;
  country?: string;
  isp?: string;
  domain?: string;
  usage_type?: string;
  total_reports?: number;
};

type ResponseResult = {
  action?: string;
  source_ip?: string;
  executed?: boolean;
  mode?: string;
  message?: string;
  executed_at?: string;
  error?: string;
};

type Incident = {
  id: number;

  prediction: string;
  attack: boolean;
  confidence: number;
  attack_probability: number;
  threshold: number;
  model: string;
  created_at: string;

  source_ip?: string | null;
  destination_ip?: string | null;
  source_port?: number | null;
  destination_port?: number | null;
  transport_protocol?: string | null;
  observed_at?: string | null;

  threat_provider?: string | null;
  threat_intelligence?: ThreatIntelligence | null;
  enriched_at?: string | null;

  llm_provider?: string | null;
  llm_model?: string | null;
  incident_analysis?: IncidentAnalysis | null;
  analysis_status?: string | null;
  analysis_error?: string | null;
  analyzed_at?: string | null;

  review_status?: string | null;
  review_note?: string | null;
  reviewed_at?: string | null;

  response_action?: string | null;
  response_status?: string | null;
  response_result?: ResponseResult | null;
  responded_at?: string | null;
};

export default function IncidentPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();

  const [incident, setIncident] =
    useState<Incident | null>(null);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [reviewNote, setReviewNote] = useState("");
  const [selectedAction, setSelectedAction] =
    useState("BLOCK_SOURCE_IP");

  const [actionLoading, setActionLoading] =
    useState(false);

  const [actionError, setActionError] =
    useState("");

  const [actionMessage, setActionMessage] =
    useState("");

  const loadIncident = useCallback(async () => {
    try {
      setError("");

      const response = await fetch(
        `http://127.0.0.1:8000/detections/${params.id}`
      );

      if (!response.ok) {
        throw new Error("Failed to load incident");
      }

      const data: Incident = await response.json();

      setIncident(data);

      if (data.review_note) {
        setReviewNote(data.review_note);
      }

      if (data.response_action) {
        setSelectedAction(data.response_action);
      }
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unknown error"
      );
    } finally {
      setLoading(false);
    }
  }, [params.id]);

  useEffect(() => {
    loadIncident();
  }, [loadIncident]);

  useEffect(() => {
  let socket: WebSocket | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let active = true;

  const connect = () => {
    if (!active) return;

    socket = new WebSocket(
      "ws://127.0.0.1:8000/ws/events"
    );

    socket.onmessage = (message) => {
      try {
        const event = JSON.parse(message.data);

        const relevantEvents = new Set([
          "THREAT_INTELLIGENCE_UPDATED",
          "ANALYSIS_COMPLETED",
          "REVIEW_UPDATED",
          "RESPONSE_UPDATED",
        ]);

        if (
          relevantEvents.has(event.event) &&
          Number(event.detection_id) === Number(params.id)
        ) {
          loadIncident();
        }
      } catch {
        // Ignore malformed live events.
      }
    };

    socket.onerror = () => {
      socket?.close();
    };

    socket.onclose = () => {
      if (active) {
        reconnectTimer = setTimeout(connect, 2000);
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
}, [loadIncident, params.id]);

  async function submitReview(
    decision: "APPROVE" | "REJECT"
  ) {
    setActionLoading(true);
    setActionError("");
    setActionMessage("");

    try {
      const response = await fetch(
        `http://127.0.0.1:8000/detections/${params.id}/review`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            decision,
            action:
              decision === "APPROVE"
                ? selectedAction
                : null,
            note: reviewNote.trim() || null,
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || "Review failed"
        );
      }

      setActionMessage(
        decision === "APPROVE"
          ? "Incident approved successfully."
          : "Incident rejected successfully."
      );

      await loadIncident();
    } catch (err) {
      setActionError(
        err instanceof Error
          ? err.message
          : "Review failed"
      );
    } finally {
      setActionLoading(false);
    }
  }

  async function executeResponse() {
    setActionLoading(true);
    setActionError("");
    setActionMessage("");

    try {
      const response = await fetch(
        `http://127.0.0.1:8000/detections/${params.id}/respond`,
        {
          method: "POST",
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || "Response execution failed"
        );
      }

      setActionMessage(
        "Approved response executed successfully."
      );

      await loadIncident();
    } catch (err) {
      setActionError(
        err instanceof Error
          ? err.message
          : "Response execution failed"
      );
    } finally {
      setActionLoading(false);
    }
  }

  if (loading) {
    return (
      <main className="min-h-screen bg-zinc-50 px-6 py-12 text-zinc-950 dark:bg-zinc-950 dark:text-white">
        <div className="mx-auto max-w-7xl">
          <p className="text-zinc-500 dark:text-zinc-400">
            Loading incident...
          </p>
        </div>
      </main>
    );
  }

  if (error || !incident) {
    return (
      <main className="min-h-screen bg-zinc-50 px-6 py-12 dark:bg-zinc-950">
        <div className="mx-auto max-w-7xl text-red-500">
          {error || "Incident not found"}
        </div>
      </main>
    );
  }

  const analysis = incident.incident_analysis;
  const threat = incident.threat_intelligence;
  const response = incident.response_result;

  return (
    <main className="min-h-screen bg-zinc-50 text-zinc-950 transition-colors dark:bg-zinc-950 dark:text-white">
      <div className="mx-auto max-w-7xl px-6 py-10">
        <div className="mb-8 flex items-center justify-between">
          <button
            onClick={() => router.push("/")}
            className="text-sm font-medium text-zinc-600 transition hover:text-zinc-950 dark:text-zinc-400 dark:hover:text-white"
          >
            ← Back to dashboard
          </button>

          <ThemeToggle />
        </div>

        <header className="mb-8 flex flex-col justify-between gap-5 md:flex-row md:items-end">
          <div>
            <p className="text-sm font-semibold uppercase tracking-[0.35em] text-emerald-500 dark:text-emerald-400">
              Sentinel Incident
            </p>

            <h1 className="mt-2 text-4xl font-bold tracking-tight">
              Detection #{incident.id}
            </h1>

            <p className="mt-2 text-sm text-zinc-500 dark:text-zinc-400">
              {new Date(
                incident.created_at
              ).toLocaleString()}
            </p>
          </div>

          <div className="flex flex-wrap gap-2">
            <Badge
              text={incident.prediction}
              type={incident.attack ? "danger" : "safe"}
            />

            {analysis?.severity && (
              <SeverityBadge
                severity={analysis.severity}
              />
            )}

            {incident.review_status && (
              <ReviewBadge
                status={incident.review_status}
              />
            )}
          </div>
        </header>

        <section className="grid gap-5 lg:grid-cols-3">
          <InfoCard
            title="ML Detection"
            items={[
              ["Prediction", incident.prediction],
              [
                "Confidence",
                `${(incident.confidence * 100).toFixed(2)}%`,
              ],
              [
                "Attack Probability",
                `${(
                  incident.attack_probability * 100
                ).toFixed(2)}%`,
              ],
              ["Model", incident.model],
            ]}
          />

          <InfoCard
            title="Network"
            items={[
              [
                "Source IP",
                incident.source_ip || "Unknown",
              ],
              [
                "Destination IP",
                incident.destination_ip || "Unknown",
              ],
              [
                "Source Port",
                incident.source_port ?? "Unknown",
              ],
              [
                "Destination Port",
                incident.destination_port ?? "Unknown",
              ],
              [
                "Protocol",
                incident.transport_protocol || "Unknown",
              ],
            ]}
          />

          <InfoCard
            title="Threat Intelligence"
            items={[
              [
                "Provider",
                incident.threat_provider || "Not available",
              ],
              [
                "Abuse Score",
                threat?.abuse_confidence_score ?? "Unknown",
              ],
              [
                "Whitelisted",
                threat?.is_whitelisted === undefined
                  ? "Unknown"
                  : threat.is_whitelisted
                    ? "Yes"
                    : "No",
              ],
              [
                "Country",
                threat?.country || "Unknown",
              ],
              [
                "ISP",
                threat?.isp || "Unknown",
              ],
              [
                "Reports",
                threat?.total_reports ?? "Unknown",
              ],
            ]}
          />
        </section>

        {analysis && (
          <section className="mt-6 rounded-2xl border border-zinc-200 bg-white p-7 shadow-sm transition-colors dark:border-zinc-800 dark:bg-zinc-900 dark:shadow-none">
            <div className="mb-6">
              <p className="text-xs font-semibold uppercase tracking-[0.3em] text-zinc-500">
                AI Incident Analysis
              </p>

              <h2 className="mt-2 text-2xl font-semibold">
                {analysis.likely_activity ||
                  "Incident Analysis"}
              </h2>
            </div>

            <div className="grid gap-5 lg:grid-cols-2">
              <AnalysisBox
                title="Summary"
                text={analysis.summary}
              />

              <AnalysisBox
                title="Severity Reason"
                text={analysis.severity_reason}
              />
            </div>

            <div className="mt-5 grid gap-5 lg:grid-cols-3">
              <ListBox
                title="Reasoning"
                items={analysis.reasoning}
              />

              <ListBox
                title="Risk Factors"
                items={analysis.risk_factors}
              />

              <ListBox
                title="Recommended Actions"
                items={analysis.recommended_actions}
              />
            </div>

            {analysis.analyst_note && (
              <div className="mt-5 rounded-xl border border-zinc-200 bg-zinc-50 p-5 dark:border-zinc-700 dark:bg-zinc-950">
                <p className="mb-2 text-sm font-semibold">
                  Analyst Note
                </p>

                <p className="text-sm leading-6 text-zinc-600 dark:text-zinc-400">
                  {analysis.analyst_note}
                </p>
              </div>
            )}
          </section>
        )}

        <section className="mt-6 grid gap-5 lg:grid-cols-2">
          <InfoCard
            title="Human Review"
            items={[
              [
                "Status",
                incident.review_status || "Unknown",
              ],
              [
                "Note",
                incident.review_note ||
                  "No review note",
              ],
              [
                "Reviewed At",
                incident.reviewed_at
                  ? new Date(
                      incident.reviewed_at
                    ).toLocaleString()
                  : "Not reviewed",
              ],
            ]}
          />

          <InfoCard
            title="Response"
            items={[
              [
                "Action",
                incident.response_action || "None",
              ],
              [
                "Status",
                incident.response_status ||
                  "NOT_STARTED",
              ],
              [
                "Mode",
                response?.mode || "Not executed",
              ],
              [
                "Responded At",
                incident.responded_at
                  ? new Date(
                      incident.responded_at
                    ).toLocaleString()
                  : "Not executed",
              ],
            ]}
          />
        </section>

        {incident.attack &&
  incident.analysis_status === "COMPLETED" && (
    <section className="mt-6 rounded-2xl border border-zinc-200 bg-white p-7 shadow-sm dark:border-zinc-800 dark:bg-zinc-900 dark:shadow-none">
      <div className="mb-6">
        <p className="text-xs font-semibold uppercase tracking-[0.3em] text-emerald-600 dark:text-emerald-400">
          Human Decision Layer
        </p>

        <h2 className="mt-2 text-2xl font-semibold">
          Incident Response Control
        </h2>

        <p className="mt-2 text-sm text-zinc-600 dark:text-zinc-400">
          Review the evidence above before authorizing
          any response action.
        </p>
      </div>

      {incident.review_status === "PENDING" && (
        <div className="space-y-5">
          <div>
            <label className="mb-2 block text-sm font-medium">
              Response Action
            </label>

            <select
              value={selectedAction}
              onChange={(event) =>
                setSelectedAction(event.target.value)
              }
              className="w-full rounded-xl border border-zinc-300 bg-white px-4 py-3 text-sm outline-none transition focus:border-emerald-500 dark:border-zinc-700 dark:bg-zinc-950"
            >
              <option value="BLOCK_SOURCE_IP">
                Block Source IP
              </option>

              <option value="LOG_ONLY">
                Log Only
              </option>
            </select>
          </div>

          <div>
            <label className="mb-2 block text-sm font-medium">
              Analyst Note
            </label>

            <textarea
              value={reviewNote}
              onChange={(event) =>
                setReviewNote(event.target.value)
              }
              placeholder="Explain why you are approving or rejecting this incident..."
              rows={4}
              className="w-full resize-none rounded-xl border border-zinc-300 bg-white px-4 py-3 text-sm outline-none transition focus:border-emerald-500 dark:border-zinc-700 dark:bg-zinc-950"
            />
          </div>

          <div className="flex flex-col gap-3 sm:flex-row sm:justify-end">
            <button
              disabled={actionLoading}
              onClick={() =>
                submitReview("REJECT")
              }
              className="rounded-xl border border-red-300 px-5 py-3 text-sm font-semibold text-red-600 transition hover:bg-red-50 disabled:opacity-50 dark:border-red-900 dark:text-red-400 dark:hover:bg-red-950/30"
            >
              Reject Incident
            </button>

            <button
              disabled={actionLoading}
              onClick={() =>
                submitReview("APPROVE")
              }
              className="rounded-xl bg-emerald-600 px-5 py-3 text-sm font-semibold text-white transition hover:bg-emerald-500 disabled:opacity-50"
            >
              {actionLoading
                ? "Processing..."
                : "Approve Response"}
            </button>
          </div>
        </div>
      )}

      {incident.review_status === "APPROVED" &&
        incident.response_status === "PENDING" && (
          <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-5 dark:border-emerald-900 dark:bg-emerald-950/20">
            <p className="font-semibold text-emerald-800 dark:text-emerald-300">
              Response approved
            </p>

            <p className="mt-2 text-sm text-emerald-700 dark:text-emerald-400">
              Authorized action:{" "}
              {incident.response_action}
            </p>

            <button
              disabled={actionLoading}
              onClick={executeResponse}
              className="mt-5 rounded-xl bg-emerald-600 px-5 py-3 text-sm font-semibold text-white transition hover:bg-emerald-500 disabled:opacity-50"
            >
              {actionLoading
                ? "Executing..."
                : "Execute Approved Response"}
            </button>
          </div>
        )}

      {incident.review_status === "REJECTED" && (
        <div className="rounded-xl border border-zinc-200 bg-zinc-50 p-5 dark:border-zinc-700 dark:bg-zinc-950">
          <p className="font-semibold">
            Incident rejected
          </p>

          <p className="mt-2 text-sm text-zinc-600 dark:text-zinc-400">
            No response action will be executed.
          </p>
        </div>
      )}

      {incident.response_status === "EXECUTED" && (
        <div className="rounded-xl border border-blue-200 bg-blue-50 p-5 dark:border-blue-900 dark:bg-blue-950/20">
          <p className="font-semibold text-blue-800 dark:text-blue-300">
            Response completed
          </p>

          <p className="mt-2 text-sm text-blue-700 dark:text-blue-400">
            {incident.response_result?.message ||
              "The approved response was executed successfully."}
          </p>
        </div>
      )}

      {actionMessage && (
        <p className="mt-5 text-sm font-medium text-emerald-600 dark:text-emerald-400">
          {actionMessage}
        </p>
      )}

      {actionError && (
        <p className="mt-5 text-sm font-medium text-red-600 dark:text-red-400">
          {actionError}
        </p>
      )}
    </section>
  )}

        {response?.message && (
          <section className="mt-5 rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm dark:border-zinc-800 dark:bg-zinc-900 dark:shadow-none">
            <p className="text-xs font-semibold uppercase tracking-[0.25em] text-zinc-500">
              Response Result
            </p>

            <p className="mt-3 text-sm leading-6 text-zinc-700 dark:text-zinc-300">
              {response.message}
            </p>
          </section>
        )}
      </div>
    </main>
  );
}

function InfoCard({
  title,
  items,
}: {
  title: string;
  items: [string, string | number][];
}) {
  return (
    <div className="rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm transition-colors dark:border-zinc-800 dark:bg-zinc-900 dark:shadow-none">
      <h2 className="mb-5 text-lg font-semibold">
        {title}
      </h2>

      <div className="space-y-4">
        {items.map(([label, value]) => (
          <div
            key={label}
            className="flex items-start justify-between gap-5 border-b border-zinc-200 pb-3 last:border-0 last:pb-0 dark:border-zinc-800"
          >
            <span className="text-sm text-zinc-500">
              {label}
            </span>

            <span className="max-w-[65%] break-words text-right text-sm font-medium text-zinc-800 dark:text-zinc-200">
              {String(value)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function AnalysisBox({
  title,
  text,
}: {
  title: string;
  text?: string;
}) {
  return (
    <div className="rounded-xl border border-zinc-200 bg-zinc-50 p-5 dark:border-zinc-800 dark:bg-zinc-950">
      <h3 className="mb-2 font-semibold">
        {title}
      </h3>

      <p className="text-sm leading-6 text-zinc-600 dark:text-zinc-400">
        {text || "Not available"}
      </p>
    </div>
  );
}

function ListBox({
  title,
  items,
}: {
  title: string;
  items?: string[];
}) {
  return (
    <div className="rounded-xl border border-zinc-200 bg-zinc-50 p-5 dark:border-zinc-800 dark:bg-zinc-950">
      <h3 className="mb-3 font-semibold">
        {title}
      </h3>

      <ul className="space-y-3 text-sm leading-6 text-zinc-600 dark:text-zinc-400">
        {items?.length ? (
          items.map((item, index) => (
            <li
              key={index}
              className="flex gap-3"
            >
              <span className="text-emerald-500">
                •
              </span>

              <span>{item}</span>
            </li>
          ))
        ) : (
          <li>None</li>
        )}
      </ul>
    </div>
  );
}

function Badge({
  text,
  type,
}: {
  text: string;
  type: "danger" | "safe";
}) {
  return (
    <span
      className={`rounded-full px-4 py-2 text-xs font-semibold ${
        type === "danger"
          ? "bg-red-500/10 text-red-600 dark:bg-red-500/15 dark:text-red-400"
          : "bg-emerald-500/10 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-400"
      }`}
    >
      {text}
    </span>
  );
}

function ReviewBadge({
  status,
}: {
  status: string;
}) {
  const classes: Record<string, string> = {
    PENDING:
      "bg-yellow-500/10 text-yellow-700 dark:bg-yellow-500/15 dark:text-yellow-400",

    APPROVED:
      "bg-blue-500/10 text-blue-700 dark:bg-blue-500/15 dark:text-blue-400",

    REJECTED:
      "bg-zinc-200 text-zinc-700 dark:bg-zinc-700 dark:text-zinc-200",

    NOT_REQUIRED:
      "bg-zinc-200 text-zinc-700 dark:bg-zinc-700 dark:text-zinc-300",
  };

  return (
    <span
      className={`rounded-full px-4 py-2 text-xs font-semibold ${
        classes[status] ||
        "bg-zinc-200 text-zinc-700 dark:bg-zinc-700 dark:text-zinc-300"
      }`}
    >
      {status}
    </span>
  );
}

function SeverityBadge({
  severity,
}: {
  severity: string;
}) {
  const classes: Record<string, string> = {
    LOW:
      "bg-emerald-500/10 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-400",

    MEDIUM:
      "bg-yellow-500/10 text-yellow-700 dark:bg-yellow-500/15 dark:text-yellow-400",

    HIGH:
      "bg-orange-500/10 text-orange-700 dark:bg-orange-500/15 dark:text-orange-400",

    CRITICAL:
      "bg-red-500/10 text-red-700 dark:bg-red-500/15 dark:text-red-400",
  };

  return (
    <span
      className={`rounded-full px-4 py-2 text-xs font-semibold ${
        classes[severity] ||
        "bg-zinc-200 text-zinc-700 dark:bg-zinc-700 dark:text-zinc-300"
      }`}
    >
      {severity}
    </span>
  );
}
