from __future__ import annotations

import unittest

from provenance_api.risk import calculate_score, risk_level


class RiskLevelTests(unittest.TestCase):
    def test_bands(self) -> None:
        self.assertEqual(risk_level(0), "low")
        self.assertEqual(risk_level(24), "low")
        self.assertEqual(risk_level(25), "medium")
        self.assertEqual(risk_level(49), "medium")
        self.assertEqual(risk_level(50), "high")
        self.assertEqual(risk_level(74), "high")
        self.assertEqual(risk_level(75), "critical")
        self.assertEqual(risk_level(100), "critical")


class CalculateScoreTests(unittest.TestCase):
    def test_clean_resource(self) -> None:
        score = calculate_score(
            severities=[],
            has_sbom=True,
            has_license=True,
            has_provenance=True,
            lifecycle_state="staged",
            license_spdx_id="MIT",
            license_allowlist=["MIT"],
        )
        self.assertEqual(score, 0)
        self.assertEqual(risk_level(score), "low")

    def test_severity_points_case_insensitive(self) -> None:
        score = calculate_score(
            severities=["CRITICAL", "High", "MEDIUM", "low"],
            has_sbom=True,
            has_license=True,
            has_provenance=True,
            lifecycle_state="released",
        )
        self.assertEqual(score, 40 + 25 + 10 + 5)
        self.assertEqual(risk_level(score), "critical")

    def test_each_severity(self) -> None:
        for severity, expected in (
            ("critical", 40),
            ("high", 25),
            ("medium", 10),
            ("low", 5),
        ):
            with self.subTest(severity=severity):
                score = calculate_score(
                    severities=[severity],
                    has_sbom=True,
                    has_license=True,
                    has_provenance=True,
                    lifecycle_state="staged",
                )
                self.assertEqual(score, expected)

    def test_missing_evidence_five_each(self) -> None:
        score = calculate_score(
            severities=[],
            has_sbom=False,
            has_license=False,
            has_provenance=False,
            lifecycle_state="staged",
        )
        self.assertEqual(score, 15)
        self.assertEqual(risk_level(score), "low")

        score = calculate_score(
            severities=[],
            has_sbom=False,
            has_license=True,
            has_provenance=False,
            lifecycle_state="staged",
        )
        self.assertEqual(score, 10)

    def test_blocked_state_adds_twenty(self) -> None:
        for state in ("withdrawn", "quarantined"):
            with self.subTest(state=state):
                score = calculate_score(
                    severities=[],
                    has_sbom=True,
                    has_license=True,
                    has_provenance=True,
                    lifecycle_state=state,
                )
                self.assertEqual(score, 20)

    def test_non_blocked_state_adds_nothing(self) -> None:
        for state in ("staged", "released"):
            with self.subTest(state=state):
                score = calculate_score(
                    severities=[],
                    has_sbom=True,
                    has_license=True,
                    has_provenance=True,
                    lifecycle_state=state,
                )
                self.assertEqual(score, 0)

    def test_allowlist_missing_license_adds_ten(self) -> None:
        score = calculate_score(
            severities=[],
            has_sbom=True,
            has_license=False,
            has_provenance=True,
            lifecycle_state="staged",
            license_spdx_id=None,
            license_allowlist=["MIT", "Apache-2.0"],
        )
        # 5 for the missing license evidence plus 10 for the breach.
        self.assertEqual(score, 15)

    def test_allowlist_denied_license_adds_ten(self) -> None:
        score = calculate_score(
            severities=[],
            has_sbom=True,
            has_license=True,
            has_provenance=True,
            lifecycle_state="staged",
            license_spdx_id="GPL-3.0",
            license_allowlist=["MIT", "Apache-2.0"],
        )
        self.assertEqual(score, 10)

    def test_allowlist_accepted_license_adds_nothing(self) -> None:
        score = calculate_score(
            severities=[],
            has_sbom=True,
            has_license=True,
            has_provenance=True,
            lifecycle_state="staged",
            license_spdx_id="MIT",
            license_allowlist=["MIT", "Apache-2.0"],
        )
        self.assertEqual(score, 0)

    def test_empty_allowlist_never_denies(self) -> None:
        score = calculate_score(
            severities=[],
            has_sbom=True,
            has_license=False,
            has_provenance=True,
            lifecycle_state="staged",
            license_spdx_id=None,
            license_allowlist=[],
        )
        # Only the missing-evidence penalty applies.
        self.assertEqual(score, 5)

    def test_no_policy_never_denies_license(self) -> None:
        score = calculate_score(
            severities=[],
            has_sbom=True,
            has_license=False,
            has_provenance=True,
            lifecycle_state="staged",
        )
        self.assertEqual(score, 5)

    def test_score_is_capped_at_one_hundred(self) -> None:
        score = calculate_score(
            severities=["critical", "critical", "critical"],
            has_sbom=False,
            has_license=False,
            has_provenance=False,
            lifecycle_state="withdrawn",
            license_spdx_id=None,
            license_allowlist=["MIT"],
        )
        self.assertEqual(score, 100)
        self.assertEqual(risk_level(score), "critical")

    def test_combined_score_and_levels(self) -> None:
        # One medium alert (10) + one missing evidence (5) = 15 -> low.
        score = calculate_score(
            severities=["medium"],
            has_sbom=False,
            has_license=True,
            has_provenance=True,
            lifecycle_state="staged",
        )
        self.assertEqual(score, 15)
        self.assertEqual(risk_level(score), "low")

        # One high alert (25) + blocked state (20) = 45 -> medium.
        score = calculate_score(
            severities=["high"],
            has_sbom=True,
            has_license=True,
            has_provenance=True,
            lifecycle_state="quarantined",
        )
        self.assertEqual(score, 45)
        self.assertEqual(risk_level(score), "medium")

        # One critical (40) + one high (25) = 65 -> high.
        score = calculate_score(
            severities=["critical", "high"],
            has_sbom=True,
            has_license=True,
            has_provenance=True,
            lifecycle_state="staged",
        )
        self.assertEqual(score, 65)
        self.assertEqual(risk_level(score), "high")


if __name__ == "__main__":
    unittest.main()
