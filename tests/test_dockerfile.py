import json
import re
import unittest
from pathlib import Path


DOCKERFILE = Path(__file__).resolve().parents[1] / "Dockerfile"


def _instruction(name):
    match = re.search(rf"^{name}\s+(.+)$", DOCKERFILE.read_text(), re.MULTILINE)
    return match.group(1) if match else None


class DockerfileTests(unittest.TestCase):
    def test_entrypoint_runs_kopf_under_tini(self):
        # kopf as PID 1 neither reaps the bw processes it orphans nor gets the
        # kernel's default SIGTERM handling (#108).
        entrypoint = json.loads(_instruction("ENTRYPOINT"))

        self.assertEqual(["/sbin/tini", "--", "kopf", "run"], entrypoint[:4])

    def test_tini_is_pinned_to_an_exact_alpine_revision(self):
        # Alpine drops old revisions; an exact pin fails loudly instead of
        # drifting (operator-image.md, Gotchas).
        dockerfile = DOCKERFILE.read_text()

        self.assertRegex(dockerfile, r"(?m)^ARG TINI_VERSION=\S+-r\d+$")
        self.assertIn("tini=${TINI_VERSION}", dockerfile)


if __name__ == "__main__":
    unittest.main()
