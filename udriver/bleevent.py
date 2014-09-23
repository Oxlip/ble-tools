import logging
import threading

class BleEvent(object):

    def __init__(self, options, callback = None, debug = False):
        self.options = options
        self.callback = callback
        self.debug = debug
        self.lock  = threading.Lock()
        self.lock.acquire()
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
                self.lock.release()
            return True
        except Exception, e:
            if self.debug:
                logging.exception(e)
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
        is_taken = False
        for event in self.events:
            is_taken |= event.notify(obj)
        if not is_taken:
            self.miss_events.append((time.time(), obj))


manager = BleEventManager()

def wait_for_event(options = None, timeout = 10, debug = False):
    event = BleEvent(options, debug = debug)
    manager.register(event)
    event.lock.acquire()
    return event.obj
