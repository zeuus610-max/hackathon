"""Timestamp normalization to UTC, and the honest limits of clock verification."""

from bisect import bisect_left
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

UTC = timezone.utc
IST = timezone(timedelta(hours=5, minutes=30), "IST")

WALL_FORMATS = ("%d/%m/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M")


@dataclass(frozen=True)
class ClockSpec:
    evidence_id: str
    system: str
    kind: str
    label: str
    rule: str
    verifiable: bool


CLOCK_SPECS: dict[str, ClockSpec] = {}


def _spec(evidence_id, system, kind, label, rule, verifiable):
    CLOCK_SPECS[evidence_id] = ClockSpec(evidence_id, system, kind, label, rule, verifiable)


# Recorded in UTC: trustworthy to the second, used as the reconciliation baseline.
for _id, _system in (
    ("E01", "LedgerOne"),
    ("E03", "SSO"),
    ("E15", "PrivateLink"),
    ("E18", "LedgerOne"),
    ("E19", "LedgerOne"),
):
    _spec(_id, _system, "utc", "UTC as recorded", "Column is already UTC ISO-8601.", True)

# Recorded in India wall time with no offset in the string.
_spec(
    "E02",
    "HelpDeskr",
    "wall_ist",
    "UTC+05:30 wall clock",
    "dd/mm/yyyy HH:MM:SS with no offset marker; 5h30m is subtracted.",
    True,
)
_spec(
    "E13",
    "HelpDeskr",
    "wall_ist",
    "UTC+05:30 wall clock",
    'Chat export declares "timezone": "local"; wall time is shifted to UTC.',
    True,
)

# Epoch seconds, but from a clock the case file says runs fast and nothing attests to.
_spec(
    "E05",
    "BlueVault",
    "epoch_unverified",
    "Unix epoch, unattested clock",
    "Seconds since epoch taken at face value, then bounded against UTC streams.",
    False,
)


def iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc(text: str) -> datetime | None:
    if not text:
        return None
    try:
        stamp = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    return stamp.astimezone(UTC)


def parse_wall(text: str, tz=IST) -> datetime | None:
    if not text:
        return None
    text = text.strip().replace("T", " ").replace("Z", "")
    for fmt in WALL_FORMATS:
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=tz).astimezone(UTC)
        except ValueError:
            continue
    return None


def to_utc_ms(evidence_id: str, raw: str) -> tuple[int | None, str | None]:
    spec = CLOCK_SPECS.get(evidence_id)
    if spec is None:
        return None, f"no clock rule registered for {evidence_id}"
    if spec.kind == "epoch_unverified":
        try:
            return int(float(raw.strip()) * 1000), None
        except (TypeError, ValueError):
            return None, f"epoch_unexpected:{raw!r}"
    moment = parse_utc(raw) if spec.kind == "utc" else parse_wall(raw)
    if moment is None:
        return None, f"unparsed:{raw!r}"
    return int(moment.timestamp() * 1000), None


def day_profile(moment_ms_list, bucket_minutes=60):
    """Activity counts per time-of-day bucket, for phase comparison."""
    profile = Counter()
    for ms in moment_ms_list:
        dt = datetime.fromtimestamp(ms / 1000, UTC)
        profile[dt.hour * (60 // bucket_minutes) + dt.minute // bucket_minutes] += 1
    return profile


def bound_offset(candidate_ms, reference_ms, max_lag_minutes=180, bucket_minutes=10):
    """Say how far an unattested clock could sit from trustworthy streams, honestly.

    Two failure modes are reported rather than papered over. A phase fit on hourly
    profiles only locks when the candidate stream has a sharp shape; and a
    nearest-neighbour gap only means anything when the reference stream is sparse.
    E01/E03/E15 together run at roughly one event per second, so a sub-second
    "match" is what chance produces, not evidence of an aligned clock.
    """
    import math

    if not candidate_ms or not reference_ms:
        return {"verdict": "insufficient_data", "best_lag_minutes": None}

    ref_sorted = sorted(reference_ms)
    span_s = max((ref_sorted[-1] - ref_sorted[0]) / 1000, 1)
    density = len(ref_sorted) / span_s

    deltas = []
    for ms in candidate_ms:
        i = bisect_left(ref_sorted, ms)
        nearest = [ref_sorted[j] for j in (i - 1, i) if 0 <= j < len(ref_sorted)]
        if nearest:
            deltas.append(ms - min(nearest, key=lambda r: abs(r - ms)))
    if not deltas:
        return {"verdict": "insufficient_data", "best_lag_minutes": None}

    within_1s = sum(1 for d in deltas if abs(d) <= 1000)
    observed_coincidence = within_1s / len(deltas)
    # Poisson chance of at least one reference event inside a +/-1s window.
    chance_coincidence = 1 - math.exp(-2 * density)

    ref_profile = day_profile(reference_ms, bucket_minutes)
    cand_profile = day_profile(candidate_ms, bucket_minutes)
    slots = max(ref_profile) + 1
    ref_vals = [ref_profile.get(s, 0) for s in range(slots)]
    cand_vals = [cand_profile.get(s, 0) for s in range(slots)]
    ref_mean = sum(ref_vals) / slots
    cand_mean = sum(cand_vals) / slots

    scores = []
    for lag in range(-max_lag_minutes, max_lag_minutes + 1):
        num = sum(
            (cand_vals[s] - cand_mean) * (ref_vals[(s - lag) % slots] - ref_mean)
            for s in range(slots)
        )
        scores.append((num, lag))
    peak = max(s for s, _ in scores)
    best_lag = next(l for s, l in scores if s == peak)
    values = [s for s, _ in scores]
    mean = sum(values) / len(values)
    sd = math.sqrt(sum((v - mean) ** 2 for v in values) / len(values)) or 1.0
    prominence = (peak - mean) / sd
    near_peak = sum(1 for s, _ in scores if s >= peak - 0.05 * abs(peak))
    span_minutes = near_peak * bucket_minutes
    identifiable = prominence > 3.0 and span_minutes <= bucket_minutes * 2

    return {
        "verdict": "identified" if identifiable else "not_identifiable",
        "best_lag_minutes": best_lag,
        "best_lag_s": best_lag * bucket_minutes * 60 if identifiable else None,
        "peak_prominence_sigma": round(prominence, 2),
        "indistinguishable_span_minutes": span_minutes,
        "observed_coincidence_within_1s": round(observed_coincidence, 3),
        "chance_coincidence_within_1s": round(chance_coincidence, 3),
        "reference_event_density_per_second": round(density, 3),
        "comparable_events": len(deltas),
        "median_nearest_gap_s": round(sorted(deltas)[len(deltas) // 2] / 1000, 1),
        "method": (
            f"hourly-profile phase fit at {bucket_minutes}-minute resolution, +/-{max_lag_minutes}m, "
            "against E01/E03/E15"
        ),
    }


def twin_links(events_a, events_b, tolerance_s=900):
    """Count (ip/24, time-proximity) pairs between two event streams.

    events_* are (ts_ms, src_24) tuples. Returns match count; used to show how the
    answer moves when an unattested clock is shifted, which is the real argument
    for normalizing before correlating.
    """
    by_key: dict[str, list[int]] = {}
    for ms, key in events_b:
        if key:
            by_key.setdefault(key, []).append(ms)
    for times in by_key.values():
        times.sort()
    tol = tolerance_s * 1000
    matches = 0
    for ms, key in events_a:
        times = by_key.get(key)
        if not times:
            continue
        i = bisect_left(times, ms)
        if any(abs(times[j] - ms) <= tol for j in (i - 1, i) if 0 <= j < len(times)):
            matches += 1
    return matches


def fragility_curve(events_a, events_b, offsets_s):
    """Twin-link count for each assumed offset on stream A."""
    return [
        {"offset_s": off, "links": twin_links([(ms + off * 1000, k) for ms, k in events_a], events_b)}
        for off in offsets_s
    ]
