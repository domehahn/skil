#!/usr/bin/env python3
"""Regression tests for differential fixture selection."""

import unittest

from run_differential import select_fixtures


class SelectFixturesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.properties = [
            {
                "id": "ASP-01.01",
                "fixtures": [
                    {"fixture": "static-full", "suite": "static", "status": "FULL"},
                    {"fixture": "semantic-full", "suite": "semantic", "status": "FULL"},
                    {
                        "fixture": "semantic-design-difference",
                        "suite": "semantic",
                        "status": "DIFFERENT_BY_DESIGN",
                    },
                ],
            },
            {
                "id": "ASP-01.02",
                "fixtures": [
                    {"fixture": "implicit-static", "status": "FULL"},
                    {
                        "fixture": "provider-design-difference",
                        "suite": "provider",
                        "status": "DIFFERENT_BY_DESIGN",
                    },
                ],
            },
        ]

    def fixture_names(self, **kwargs: object) -> list[str]:
        return [
            fixture["fixture"]
            for _, fixture in select_fixtures(self.properties, **kwargs)
        ]

    def test_suite_filter_applies_to_each_fixture(self) -> None:
        self.assertEqual(
            self.fixture_names(suite="semantic"),
            ["semantic-full", "semantic-design-difference"],
        )

    def test_missing_suite_defaults_to_static(self) -> None:
        self.assertEqual(
            self.fixture_names(suite="static"),
            ["static-full", "implicit-static"],
        )

    def test_skip_different_by_design_applies_to_each_fixture(self) -> None:
        self.assertEqual(
            self.fixture_names(skip_different_by_design=True),
            ["static-full", "semantic-full", "implicit-static"],
        )

    def test_suite_and_status_filters_compose(self) -> None:
        self.assertEqual(
            self.fixture_names(
                suite="semantic", skip_different_by_design=True
            ),
            ["semantic-full"],
        )


if __name__ == "__main__":
    unittest.main()
