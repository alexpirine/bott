# coding: utf-8
# Copyright (c) Alexandre Syenchuk, 2016

class block(object):
    class exit(Exception):
      pass

    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self.value.__enter__()

    def __exit__(self, etype, value, traceback):
        error = self.value.__exit__(etype, value, traceback)
        if etype == self.exit:
            return True
        return error