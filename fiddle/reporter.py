from doit.reporter import ConsoleReporter
import logging

class FiddleReporter(ConsoleReporter):
    def write(self, text):
        if logging.getLogger().level <= logging.DEBUG:
            ConsoleReporter.write(self, text)
