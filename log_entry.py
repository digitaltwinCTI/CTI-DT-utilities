class LogEntry:
    def __init__(self, level=None, timestamp=None, ip_addr_host=None, program=None, message=None,
                 ip_addr_external=None):
        self.loglevel = level
        self.timestamp = timestamp
        self.ip_addr_host = ip_addr_host
        self.program = program
        self.message = message
        self.ip_addr_external = ip_addr_external

    def __repr__(self):
        return f'{self.loglevel} {self.timestamp} {self.ip_addr_host} {self.program} {self.message}'

    def add_message_element(self, data):
        self.message = self.message + data
