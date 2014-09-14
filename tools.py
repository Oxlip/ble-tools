import os
import json
import logging.config

class ConsoleColorFormatter(logging.Formatter):
   color = {
    'WARNING': 3,
    'INFO': 7,
    'DEBUG': 4,
    'CRITICAL': 3,
    'ERROR': 1
   }

   def __init__(self, _format):
      super(ConsoleColorFormatter, self).__init__(_format)

   def _colorize(self, string):
      return '\033[3{}{}{}\033[0m'.format(self.color[string], ";1m", string)

   def format(self, record):
      record.levelname = self._colorize(record.levelname)
      return super(ConsoleColorFormatter, self).format(record)

logpath='configs/logging.json'
if os.path.exists(logpath):
   with open(logpath, 'rt') as f:
      config = json.load(f)
   logging.config.dictConfig(config)
else:
   logging.basicConfig(level=logging.INFO)
