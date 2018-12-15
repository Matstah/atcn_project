from __future__ import print_function
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from os import path
import traceback
import time
import sys

SLEEP_TIME = 5

def red(str):
    return '\033[{}m'.format(91) + str + '\033[0m'
def green(str):
    return '\033[{}m'.format(92) + str + '\033[0m'

class Controller(object):

    def __init__(self, sw_name):
        self.sw_name = sw_name
        self.thrift_port = 9090
        self.controller = SimpleSwitchAPI(self.thrift_port)
        self.cpu_port =  8

    def run(self):
        script = path.basename(__file__)
        print('{}: Controller.run() called on {}'.format(script, self.sw_name))
        print('Reseting Bloom Filter: ', end='')
        while True:
            time.sleep(SLEEP_TIME)
            print(green('X '), end='')
            sys.stdout.flush()
            self.controller.register_reset('MyIngress.bloom_filter')

if __name__ == "__main__":
    try:
        controller = Controller('fir').run()
    except:
        print(red('CONTROLLER TERMINATED UNEXPECTEDLY! WITH ERROR:'))
        traceback.print_exc()
    else:
        print('CONTROLLER REACHED THE END')
