"""Global, on-the-fly advisory aggregation across every resource.

Unlike the per-resource vulnerability views, this summary groups all
recorded alerts by their advisory identifier. It is computed at request
time from the global alert submission order and the resource registry
order; nothing is recorded, and a restart clears every input just like
the rest of the in-process state.
"""

from __future__ import annotations

from .resources import ResourceStore
from .vulnerabilities import VulnerabilityStore, max_severity


def summarize_advisories(
    resources: ResourceStore,
    vulnerabilities: VulnerabilityStore,
    severity: str | None = None,
) -> list[dict[str, object]]:
    """Aggregate every alert by advisory identifier.

    With ``severity`` set (already normalized to lowercase), only alerts at
    that level participate; grouping, ordering and counting semantics are
    otherwise unchanged.

    Each advisory is emitted in first-appearance order, where first
    appearance follows the global submission order of the earliest matching
    alert (independent of resource registration order). The affected
    resources are listed in resource registration order, each appearing once
    regardless of how many alerts it contributes or when they were
    submitted. The count is the raw number of matching alerts for the
    advisory: duplicates are neither removed nor merged.
    """

    advisory_order: list[str] = []
    affected_sets: dict[str, set[str]] = {}
    counts: dict[str, int] = {}
    severities: dict[str, list[str]] = {}

    for resource_id, alert in vulnerabilities.list_all():
        if severity is not None and alert.severity != severity:
            continue
        if alert.advisory not in affected_sets:
            advisory_order.append(alert.advisory)
            affected_sets[alert.advisory] = set()
            counts[alert.advisory] = 0
            severities[alert.advisory] = []
        affected_sets[alert.advisory].add(resource_id)
        counts[alert.advisory] += 1
        severities[alert.advisory].append(alert.severity)

    return [
        {
            "advisory": advisory,
            "affected_resources": [
                resource.id
                for resource in resources.list_all()
                if resource.id in affected_sets[advisory]
            ],
            "advisory_count": counts[advisory],
            "max_severity": max_severity(severities[advisory]),
        }
        for advisory in advisory_order
    ]


def advisory_detail(
    resources: ResourceStore,
    vulnerabilities: VulnerabilityStore,
    advisory: str,
    severity: str | None = None,
) -> dict[str, object]:
    """Return the alert detail for one verbatim advisory identifier.

    ``advisory`` is matched verbatim, case-sensitively and without any
    trimming. With ``severity`` set (already normalized to lowercase), only
    alerts at that level participate.

    The detail is expanded in resource registration order; within a single
    resource the alerts keep their submission order, and each resource
    appears at most once. ``affected_resources`` lists, in that same
    registration order, only the resources that contribute at least one
    matching alert. Every alert object starts with ``resource_id`` and then
    echoes the single-alert registration key order. Nothing is recorded.
    """

    alerts: list[dict[str, object]] = []
    affected: list[str] = []
    for resource in resources.list_all():
        matching = [
            alert
            for alert in vulnerabilities.list_for(resource.id, severity)
            if alert.advisory == advisory
        ]
        if not matching:
            continue
        affected.append(resource.id)
        for alert in matching:
            alerts.append({"resource_id": resource.id, **alert.to_dict()})

    return {
        "advisory": advisory,
        "affected_resources": affected,
        "alerts": alerts,
    }
