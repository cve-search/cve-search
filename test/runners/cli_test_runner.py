from subprocess import run, PIPE, STDOUT


class CLITestRunner(object):
    def __init__(self):
        self.runner = None
        self.cmd = None

    def runcommand(self, cmd):
        self.cmd = cmd
        self.runner = run(
            self.cmd.split(" "),
            stdout=PIPE,
            stderr=STDOUT,
            universal_newlines=True,
            shell=False,
        )

        return self.runner
