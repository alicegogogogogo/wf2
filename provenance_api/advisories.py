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
    """Return the per-component fix recommendation view for one advisory.

    The identifier is matched verbatim and echoed back unchanged. With
    ``severity`` set (already normalized to lowercase), only alerts at that
    level participate, so under the same filter the component counts add up
    to the advisory's matching alert count in the summary and detail views.

    Components are expanded in resource registration order, aggregating the
    matching alerts inside each resource by that resource's submission
    order; the same component therefore appears at most once even when it
    hits on several resources. A component that contributes no matching
    alert is never emitted. Each entry lists exactly the resources that
    contribute a matching alert, in registration order and without
    duplicates; the count is the raw number of matching alerts for the
    component, neither deduplicated nor merged. The recommendation is the
    greatest non-empty numeric ``fixed_version`` among the matching
    alerts, using the same comparison rule as the per-resource component
    fix view; ``None`` and non-numeric candidates are ignored, and an
    empty candidate set leaves the recommendation empty. An unknown
    advisory, or a filter that matches nothing, yields an empty
    ``fixes`` array.
    """

    # component -> contributing resource ids, in first-encounter order.
    component_resources: dict[str, list[str]] = {}
    component_counts: dict[str, int] = {}
    component_versions: dict[str, list[str | None]] = {}

    for resource in resources.list_all():
        # Keep submission order within the resource so aggregation follows
        # the alert submission order documented for this view.
        per_resource_components: set[str] = set()
        for alert in vulnerabilities.list_for(resource.id, severity):
            if alert.advisory != advisory:
                continue
            if alert.component not in component_resources:
                component_resources[alert.component] = []
                component_counts[alert.component] = 0
                component_versions[alert.component] = []
            if alert.component not in per_resource_components:
                per_resource_components.add(alert.component)
                component_resources[alert.component].append(resource.id)
            component_counts[alert.component] += 1
            component_versions[alert.component].append(alert.fixed_version)

    fixes = [
        {
            "name": component,
            "affected_resources": component_resources[component],
            "advisory_count": component_counts[component],
            "recommended_version": recommended_fix_version(
                component_versions[component]
            ),
        }
        for component in component_resources
    ]

    return {"advisory": advisory, "fixes": fixes}
