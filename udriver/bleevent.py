import logging
import threading
import time

class BleEvent(object):

    def __init__(self, options, callback = None, debug = False):
        self.options = options
        self.callback = callback
        self.debug = debug
        self.event = threading.Event()
        self.event.clear()
        self.obj = None

    def notify(self, obj):
        try:
            for field, value in self.options.iteritems():
                logging.error('check for obj.%s == %s',
                              field,
                              value)
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
            if time.time() > t + (10 * 1000):
                if event.notify(obj):
                    return
        self.events.append(event)

    def notify(self, obj):
        event_count = len(self.events)
        for event in self.events:
            self.events = [ x for x in self.events if not event.notify(obj) ]
        if len(self.events) == event_count:
            self.miss_events.append((time.time(), obj))


manager = BleEventManager()

def wait_for_event(options = None, timeout = 10, debug = False):
    event = BleEvent(options, debug = debug)
    manager.register(event)
    event.event.wait(timeout)
    return event.obj
