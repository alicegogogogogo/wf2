"""Global, on-the-fly advisory aggregation across every resource.

Unlike the per-resource vulnerability views, this summary groups all
recorded alerts by their advisory identifier. It is computed at request
time from the global alert submission order and the resource registry
order; nothing is recorded, and a restart clears every input just like
the rest of the in-process state.
"""

from __future__ import annotations

from .component_fixes import recommended_fix_version
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
    """Return the per-alert detail view for a single advisory identifier.

    The identifier is matched verbatim: case-sensitive, no trimming, and it
    is echoed back unchanged. With ``severity`` set (already normalized to
    lowercase), only alerts at that level participate; ordering and
    grouping semantics are otherwise unchanged, so the matching alert count
    and highest severity always agree with the global summary view under
    the same filter.

    Alerts are expanded in resource registration order, keeping each
    resource's own submission order inside its block, so every resource
    appears at most once. ``affected_resources`` lists exactly the
    resources that contribute a matching alert, in registration order and
    without duplicates. An unknown advisory, or a filter that matches
    nothing, yields empty ``alerts`` and ``affected_resources`` arrays.
    """

    alerts: list[dict[str, object]] = []
    affected: list[str] = []
    for resource in resources.list_all():
        matched = [
            alert
            for alert in vulnerabilities.list_for(resource.id, severity)
            if alert.advisory == advisory
        ]
        if not matched:
            continue
        affected.append(resource.id)
        for alert in matched:
            alerts.append({"resource_id": resource.id, **alert.to_dict()})

    return {
        "advisory": advisory,
        "affected_resources": affected,
        "alerts": alerts,
    }


def advisory_fixes(
    resources: ResourceStore,
    vulnerabilities: VulnerabilityStore,
    advisory: str,
    severity: str | None = None,
) -> dict[str, object]:
    """Return per-component fix recommendations for a single advisory.

    The identifier is matched verbatim: case-sensitive, no trimming, and it
    is echoed back unchanged. With ``severity`` set (already normalized to
    lowercase), only alerts at that level participate; grouping, ordering
    and counting semantics are otherwise unchanged, so the component counts
    always add up to the matching alert count of the summary and detail
    views under the same filter.

    Components are aggregated from the matching alerts alone (the SBOM is
    never consulted): resources are expanded in registration order and each
    resource's alerts in submission order, so a component takes the position
    of its earliest matching alert under that traversal. A component appears
    at most once, and components without any matching alert are omitted.
    ``affected_resources`` lists exactly the resources that contribute a
    matching alert for the component, in registration order and without
    duplicates; ``advisory_count`` is the raw number of matching alerts,
    neither deduplicated nor merged. ``recommended_version`` is the greatest
    usable fixed version among the matching alerts, following the same
    dotted-decimal comparison as the per-resource component fix view:
    candidates with a non-numeric segment are ignored, and the value is
    ``None`` when no usable candidate exists. An unknown advisory, or a
    filter that matches nothing, yields an empty ``fixes`` array.
    """

    component_order: list[str] = []
    affected_sets: dict[str, set[str]] = {}
    counts: dict[str, int] = {}
    fixed_versions: dict[str, list[str | None]] = {}

    for resource in resources.list_all():
        for alert in vulnerabilities.list_for(resource.id, severity):
            if alert.advisory != advisory:
                continue
            if alert.component not in affected_sets:
                component_order.append(alert.component)
                affected_sets[alert.component] = set()
                counts[alert.component] = 0
                fixed_versions[alert.component] = []
            affected_sets[alert.component].add(resource.id)
            counts[alert.component] += 1
            fixed_versions[alert.component].append(alert.fixed_version)

    return {
        "advisory": advisory,
        "fixes": [
            {
                "name": component,
                "affected_resources": [
                    resource.id
                    for resource in resources.list_all()
                    if resource.id in affected_sets[component]
                ],
                "advisory_count": counts[component],
                "recommended_version": recommended_fix_version(
                    fixed_versions[component]
                ),
            }
            for component in component_order
        ],
    }
