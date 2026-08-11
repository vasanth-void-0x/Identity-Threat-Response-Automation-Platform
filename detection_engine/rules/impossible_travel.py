"""
detection_engine/rules/impossible_travel.py
7.5 Impossible Travel - detects two successful logins for the same user from
geographically distant locations within an unrealistic time window, using the
Haversine formula to compute great-circle distance and required travel speed.
"""

from __future__ import annotations

import math
from typing import Any

from detection_engine.base_rule import BaseDetectionRule
from models.alert import Alert
from models.event import NormalizedEvent

EARTH_RADIUS_KM = 6371.0
MAX_PLAUSIBLE_SPEED_KMH = 900  # ~ commercial jet cruising speed


def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = math.sin(d_phi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(a))


class ImpossibleTravelRule(BaseDetectionRule):
    rule_name = "impossible_travel"
    mitre_techniques = ["T1078"]

    def evaluate(self, events: list[NormalizedEvent], context: dict[str, Any]) -> list[Alert]:
        alerts: list[Alert] = []

        by_user: dict[str, list[NormalizedEvent]] = {}
        for e in events:
            if e.event_type == "logon_success" and e.user and e.latitude is not None and e.longitude is not None:
                by_user.setdefault(e.user, []).append(e)

        for user, evs in by_user.items():
            evs.sort(key=lambda x: x.timestamp)
            for prev, curr in zip(evs, evs[1:]):
                hours = (curr.timestamp - prev.timestamp).total_seconds() / 3600.0
                if hours <= 0:
                    continue
                distance_km = haversine_distance_km(prev.latitude, prev.longitude, curr.latitude, curr.longitude)
                if distance_km < 300:
                    continue  # too close to be meaningful travel
                required_speed = distance_km / hours

                if required_speed > MAX_PLAUSIBLE_SPEED_KMH:
                    alerts.append(self._make_alert(
                        title=f"Impossible travel detected for '{user}'",
                        description=(
                            f"User '{user}' logged in from {prev.city}, {prev.country} then "
                            f"{round(hours * 60)} minutes later from {curr.city}, {curr.country} - "
                            f"a distance of {round(distance_km)} km, requiring a travel speed of "
                            f"{round(required_speed)} km/h (implausible)."
                        ),
                        event_ids=[prev.event_id, curr.event_id],
                        user=user,
                        source_ip=curr.source_ip,
                        hostname=curr.hostname,
                        metadata={
                            "previous_location": f"{prev.city}, {prev.country}",
                            "current_location": f"{curr.city}, {curr.country}",
                            "time_difference_minutes": round(hours * 60, 1),
                            "distance_km": round(distance_km, 1),
                            "required_speed_kmh": round(required_speed, 1),
                        },
                        created_at=curr.timestamp,
                    ))
        return alerts
