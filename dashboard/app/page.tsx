"use client";

import { useEffect, useState } from "react";
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

export default function Home() {
  const router = useRouter();

  const [detections, setDetections] = useState<Detection[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    async function loadDetections() {
      try {
        const response = await fetch(
          "http://127.0.0.1:8000/detections"
        );

        if (!response.ok) {
          throw new Error("Failed to load detections");
        }

        const data = await response.json();

        setDetections(data);
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : "Unknown error"
        );
      } finally {
        setLoading(false);
      }
    }

    loadDetections();
  }, []);

  const total = detections.length;

  const attacks = detections.filter(
    (detection) => detection.attack
  ).length;

  const benign = total - attacks;

  const attackRate =
    total > 0
      ? ((attacks / total) * 100).toFixed(1)
      : "0.0";

  return (
    <main className="min-h-screen bg-zinc-50 text-zinc-950 transition-colors dark:bg-zinc-950 dark:text-white">
      <div className="mx-auto max-w-7xl px-6 py-10">
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

        <section className="mb-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <StatCard
            title="Total Detections"
            value={String(total)}
            description="Recorded network events"
          />

          <StatCard
            title="Attacks"
            value={String(attacks)}
            description="Flows classified as ATTACK"
          />

          <StatCard
            title="Benign"
            value={String(benign)}
            description="Flows classified as BENIGN"
          />

          <StatCard
            title="Attack Rate"
            value={`${attackRate}%`}
            description="Share of current records"
          />
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
            </div>

            <div className="hidden rounded-full bg-emerald-500/10 px-3 py-1 text-xs font-semibold text-emerald-600 sm:block dark:text-emerald-400">
              API CONNECTED
            </div>
          </div>

          {loading && (
            <div className="p-8 text-sm text-zinc-500 dark:text-zinc-400">
              Loading Sentinel detections...
            </div>
          )}

          {error && (
            <div className="p-8 text-sm text-red-500">
              {error}
            </div>
          )}

          {!loading && !error && detections.length === 0 && (
            <div className="p-8 text-sm text-zinc-500 dark:text-zinc-400">
              No detections are currently available.
            </div>
          )}

          {!loading && !error && detections.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[760px] text-left">
                <thead className="bg-zinc-50 text-xs uppercase tracking-wider text-zinc-500 dark:bg-zinc-950/50 dark:text-zinc-400">
                  <tr>
                    <th className="px-6 py-4">ID</th>
                    <th className="px-6 py-4">Prediction</th>
                    <th className="px-6 py-4">Confidence</th>
                    <th className="px-6 py-4">Model</th>
                    <th className="px-6 py-4">Created</th>
                    <th className="px-6 py-4 text-right">
                      Incident
                    </th>
                  </tr>
                </thead>

                <tbody>
                  {detections.map((detection) => (
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
                          attack={detection.attack}
                          prediction={detection.prediction}
                        />
                      </td>

                      <td className="px-6 py-4 font-medium">
                        {(detection.confidence * 100).toFixed(
                          2
                        )}
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
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </main>
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