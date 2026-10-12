"""Original outer QML state machines on the desktop; no device qualification."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


class OuterMenuTests(unittest.TestCase):
    def run_scenario(self, scenario="normal"):
        environment = os.environ.copy()
        environment["X2DII_OUTER_MENU_SCENARIO"] = scenario
        result = subprocess.run([sys.executable, "-B", str(ROOT / "tools/check_outer_menu.py")],
                                capture_output=True, text=True, encoding="utf-8", timeout=90, env=environment)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = json.loads(result.stdout)
        evidence = json.loads((Path(summary["runDirectory"]) / "RESULT.json").read_text())
        self.assertEqual(evidence["result"], "PASS")
        self.assertEqual(evidence["scenario"], scenario)
        self.assertFalse(evidence["installable"])
        self.assertEqual(evidence["cameraAccesses"], 0)
        self.assertTrue(evidence["sourceInputsUnchanged"])
        self.assertTrue(evidence["completeQtTeardown"])
        self.assertTrue(evidence["qmlTypeRegistrationsCleared"])
        self.assertEqual(evidence["registeredUnitMemory"]["sha256"], evidence["hostUnitSha256"])
        self.assertTrue(evidence["processExitVerified"])
        self.assertEqual(len(evidence["originalStockResources"]), 19)
        return evidence

    def test_original_outer_menu_stock_route_then_extension_return(self):
        evidence = self.run_scenario()
        self.assertIn("original-control-drawer-async-readiness", evidence["cases"])
        self.assertIn("original-stock-route-menu-swipe-escape-return", evidence["cases"])
        self.assertIn("extension-back-real-drawer-focus-and-bindings", evidence["cases"])
        self.assertIn("original-stock-route-after-extension-once", evidence["cases"])
        self.assertIn("original-shortcut-arguments-cover-lifecycle", evidence["cases"])
        self.assertEqual(evidence["shortcut"]["data"]["name"], "menu1")
        self.assertEqual(evidence["shortcut"]["data"]["sub"], "detail")
        self.assertTrue(evidence["shortcut"]["data"]["shortcut"])
        self.assertTrue(evidence["shortcut"]["data"]["openItem"])
        self.assertEqual(evidence["shortcut"]["opacityWhileWaiting"], 1)
        self.assertEqual(evidence["shortcut"]["opacityAfterLoaded"], 0)
        self.assertIn("original-pointer-drag-close", evidence["cases"])
        self.assertTrue(any(row["dragActive"] for row in evidence["pointerDrag"]["trace"]))
        self.assertGreater(evidence["pointerDrag"]["xBeforeRelease"], 1024 / 3)
        self.assertFalse(evidence["pointerDrag"]["activeAfterClose"])
        self.assertIn("original-leaf-prevent-swipe-binding", evidence["cases"])
        self.assertTrue(evidence["preventSwipe"]["blocked"]["preventSwipe"])
        self.assertFalse(evidence["preventSwipe"]["blocked"]["swipeEnabled"])
        self.assertFalse(any(row["dragActive"] for row in evidence["preventSwipe"]["trace"]))
        self.assertTrue(evidence["preventSwipe"]["activeAfterRelease"])
        self.assertIn("extension-unload-original-bindings-remain-live", evidence["cases"])
        self.assertTrue(evidence["extensionUnload"]["originalBindingsLive"])
        self.assertEqual(evidence["extensionUnload"]["sourceCounts"], [10, 11])
        self.assertTrue(evidence["extensionUnload"]["reattachedBeforeWholeTreeTeardown"])
        self.assertIn("original-drawer-state-focus-and-top-transitions", evidence["cases"])
        self.assertEqual(evidence["drawerTransitions"]["control"]["state"], "control_screen")
        self.assertTrue(evidence["drawerTransitions"]["controlFocus"])
        self.assertFalse(evidence["drawerTransitions"]["atTop"]["allowWritingIndicator"])
        self.assertTrue(evidence["drawerTransitions"]["atBottomControl"]["allowWritingIndicator"])
        self.assertEqual(evidence["unexpectedWarnings"], [])

    def check_dependency_failure(self, scenario):
        evidence = self.run_scenario(scenario)
        self.assertIn("outer-dependency-error-original-eleven-routes", evidence["cases"])
        self.assertIn("outer-dependency-error-original-bindings", evidence["cases"])
        self.assertEqual(evidence["dependencyFailure"]["loaderStatus"], 3)
        self.assertTrue(evidence["dependencyFailure"]["nullItem"])
        self.assertGreater(evidence["dependencyFailure"]["urlHits"], 0)
        self.assertTrue(evidence["dependencyFailure"]["expectedWarnings"])
        self.assertEqual(evidence["dependencyFailure"]["stockNames"], ["menu" + str(i) for i in range(11)])
        self.assertEqual(evidence["unexpectedWarnings"], [])
        return evidence

    def test_missing_extension_page_preserves_outer_stock_behavior(self):
        evidence = self.check_dependency_failure("missing-page")
        self.assertIsNone(evidence["dependencyFailure"]["faultSha256"])

    def test_malformed_extension_page_preserves_outer_stock_behavior(self):
        evidence = self.check_dependency_failure("malformed-page")
        self.assertIsNotNone(evidence["dependencyFailure"]["faultSha256"])


if __name__ == "__main__":
    unittest.main()
