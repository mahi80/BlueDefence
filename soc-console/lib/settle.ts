// Settle the reads of one render: a failed read becomes a visible error, never an empty "live" list.

/** Settle several reads for one render: each failed one contributes its message, the rest still show. */
export async function settle<T extends readonly unknown[]>(
  reads: { [K in keyof T]: Promise<T[K]> },
  empty: { [K in keyof T]: T[K] },
): Promise<{ values: T; errors: string[] }> {
  const res = await Promise.allSettled(reads as readonly Promise<unknown>[]);
  const errors: string[] = [];
  const values = res.map((r, i) => {
    if (r.status === "fulfilled") return r.value;
    errors.push(String((r.reason as Error)?.message ?? r.reason).slice(0, 160));
    return (empty as readonly unknown[])[i];
  }) as unknown as T;
  return { values, errors };
}
