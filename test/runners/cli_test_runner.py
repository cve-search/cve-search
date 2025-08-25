import os
from subprocess import run, PIPE, STDOUT


class CLITestRunner:
    def runcommand(self, cmd):
        env = os.environ.copy()
        env["USE_TEST_DB"] = "1"  # use test DB for subprocess
        result = run(
            cmd.split(" "), stdout=PIPE, stderr=STDOUT, universal_newlines=True, env=env
        )
        return result
