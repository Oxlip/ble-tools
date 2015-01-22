import logging
import threading
import time

class BleEvent(object):

    def __init__(self, options, callback = None, debug = False, opcode = None):
        self.options = options
        self.callback = callback
        self.debug = debug
        self.event = threading.Event()
        self.event.clear()
        self.opcode = opcode
        self.obj = None

    def notify(self, obj):
        # check if the pkt is an error responce
        try:
           if getattr(obj, 'opcode') == 0x01:
              if getattr(obj, 'req_opcode') == self.opcode:
                 self.obj = obj
                 self.event.set()
                 return True
        except:
           pass

        try:
            for field, value in self.options.iteritems():
                if self.debug:
                   needed = getattr(obj, field)
                   logging.debug('check for obj.%s, %s == %s',
                                 field, hex(needed), hex(value))
                if getattr(obj, field) != value:
                    return False
            if self.callback is not None:
                self.callback(obj)
            else:
                self.obj = obj
                self.event.set()
            return True
        except Exception, e:
            if self.debug:
                logging.exception(e)
                logging.error(dir(obj))
            return False
                    

class BleEventManager(object):

    def __init__(self):
        self.events = []
        self.miss_events = []

    def register(self, event):
        for t, obj in self.miss_events:
           if event.notify(obj):
              self.miss_events.remove((t, obj))
              return
        self.events.append(event)

    def notify(self, obj):
        event_count = len(self.events)
        self.events = [ x for x in self.events if not x.notify(obj) ]
        if len(self.events) == event_count:
            self.miss_events.append((time.time(), obj))
            logging.info('Nb of missing nb %s', len(self.miss_events))


manager = BleEventManager()

def wait_for_event(options = None, timeout = 10, debug = False, opcode = None):
    event = BleEvent(options, debug = debug, opcode = opcode)
    manager.register(event)
    event.event.wait(timeout)
    return event.obj
