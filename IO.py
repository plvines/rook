'''
Author: Paul Vines
'''

import threading
import sys


class IO (threading.Thread):
    def __init__(self, app):
        threading.Thread.__init__(self)
        self._keep_running = True
        self._app = app

        def run(self):
            while (self._keep_running):
                line = sys.stdin.readline()

                if line == "/quit\n" or line == "q\n":
                    print("quitting!")
                    self._app.stop()
                    self._keep_running = False
                elif line == "/help\n" or line == "h\n":
                    print("Commands:")
                    print("/connect (c) to connect to a server")
                    print("/list (l) to see a list of users")
                    print("/nick to change your name")
                    print("/t [username] to start a conversation with someone")
                    print("/o to send an OTR message")

                elif line == "/connect\n" or line == "c\n":
                    print("connecting")
                    self._app.connect_to_server()
                elif line[:5] == "/nick":
                    self._app.rename(line[6:-1])
                elif line == "/list\n" or line == "l\n":
                    print("querying list")
                    self._app.query_user_list()
                elif line[:2] == "/s":
                    self._app.send_server_message(line[2:])
                elif line[:2] == "/t":
                    self._app.start_convo_with(line[3:-1])
                elif line[:2] == "/o":
                    self._app.send_user_otr_message(line[3:-1])
                elif line == "u\n":
                    self._app.print_user_list()
                elif line == "/gather\n":
                    self._app.gather_data()
                else:
                    self._app.send_user_message(line[:-1])

                    def stop(self):
                        print("io stopping!")
                        self._keep_running = False
