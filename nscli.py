#!/usr/bin/env python
import cmd
import os

import sys
import json

import signal
import logging

from optparse import OptionParser
from datetime import datetime
from py9p import Error, EofError, RpcError, MAXREAD, Marshal9P, Client

from time import sleep

NAME = 'nscli'

def sig_handler(sig, frame=None):
    _ = frame  # signal passes frame
    stamp = datetime.today().isoformat()
    print('{0} caught {1} stopping {2}\n'.format(NAME, sig, stamp))
    sys.exit(0)


def formatdata(data):
    """
    for debugging

    this function takes a string and determines if it's json.  If it is
    it will return a nicely formatted form of it.

    :param data:
    :type data:
    :return:
    :rtype:
    """
    try:
        jsondata = json.loads(data)
    except ValueError:
        logger.debug("read: %sB" % len(data))
        logger.debug("doesn't looks like json")
        raise ValueError('')
    jsonstring = json.dumps(jsondata, sort_keys=True,
                            indent=4, separators=(',', ': '))
    logger.debug("looks like json")
    return jsonstring

class LocalNS(object):
    """
    a 9p server connected via filehandle
    """

    def __init__(self, handle, dotu=0, chatty=False):
        self.handle = handle
        self.fids = {}  # fids are per client
        self.reqs = {}  # reqs are per client
        self.closing = False
        self.marshal = Marshal9P(dotu=dotu, chatty=chatty)

    def read(self, l):
        if self.closing:
            return ""
        x = os.read(self.handle, l)
        while len(x) < l:
            b = os.read(self.handle, l - len(x))
            if not b:
                raise EofError("client EOF")
            x += b
        return x

    def write(self, buf):
        if self.closing:
            return len(buf)
        if os.write(self.handle, buf) != len(buf):
            raise Error("short write")

    def fileno(self):
        return self.handle

    def close(self):
        os.close(self.handle)

    def send(self, x):
        self.marshal.send(self, x)

    def recv(self):
        return self.marshal.recv(self)

    def delfid(self, fid):
        if fid in self.fids:
            self.fids[fid].ref -= 1
            if self.fids[fid].ref == 0:
                del self.fids[fid]

    def getfid(self, fid):
        if fid in self.fids:
            return self.fids[fid]
        return None


def openns(chatty=False):
    osname = sys.platform

    if osname == 'sunos5':
        nspath = '/dev/ethdrv/ns'
    elif osname == 'linux2':
        nspath = '/proc/ethdrv/ns'
    elif osname == 'windows':
        raise NotImplementedError("Windows doesn't yet support the NS fs")
    else:
        raise NotImplementedError("Wasn't expecting %s" % osname)

    tries = 1
    opened = False
    sleeptime = 5
    MAXTRIES = 60 * (1 / sleeptime)

    while not opened:
        try:
            fh = get_handle(nspath)
            opened = True
            logger.info('{0} connected to namepace\n'.format(NAME))
        except OSError as e:
            logger.info('{0} NS open failed; sleeping {1}({2}/{3})\n'.format(NAME, sleeptime, tries, MAXTRIES))
            tries += 1
            if tries > MAXTRIES:
                raise e
            sleep(sleeptime)

    if not opened:
        logger.info("{0} daemon couldn't open ns {1}\n".format(NAME, e))
        raise e

    handle = LocalNS(fh, chatty=chatty)

    return Client(handle, user='nobody', msize=MAXREAD)


def get_handle(nspath, mode=os.O_RDWR):
    fh = os.open(nspath, mode)
    return fh


class NullHandler(logging.Handler):
    """
    http://bugs.python.org/issue7052
    """

    def handle(self, record):
        pass

    def emit(self, record):
        pass

    def createLock(self):
        self.lock = None


class Cli(cmd.Cmd, object):

    def __init__(self, chatty=False):
        self.prompt = "NS> "
        self.pwd = '/'
        self.ns = openns(chatty)
        super(Cli, self).__init__()

    def do_cat(self, fname):
        self.ns.open(fname)
        print self.ns.read(MAXREAD)
        self.ns.close()

    def do_jcat(self, fname):
        """
        try to print filename as nicely formatted json
        """
        try:
            self.ns.open(fname)
        except RpcError as e:
            print "%s" % e
            return False
        data = self.ns.read(MAXREAD)
        self.ns.close()
        try:
            jsondata = json.loads(data)
        except ValueError:
            logger.debug("read: %sB" % len(data))
            logger.debug("doesn't looks like json")
            raise ValueError('')

        print json.dumps(jsondata, sort_keys=True,
                         indent=4, separators=(',', ': '))

    def do_ls(self, *args):
        """
        list the contents of the current directory
        """
        detail = False
        if args[0] == '-l':
            detail = True
            args = args[1:]

        try:
            if args:
                entries = self.ns.ls(longnames=False, args=args)
            else:
                print args
                entries = self.ns.ls()

        except RpcError as e:
            print "%s" % e
            return False

        if detail:
            for f in entries:
                print "%s" % (self.ns.stat(f)[0].tolstr())
        else:
            for f in entries:
                print self.ns.stat(f)[0].name

    def do_cd(self, path='/'):
        try:
            self.ns.cd(path)
        except RpcError as e:
            print "%s" % e
            return False

    @staticmethod
    def do_quit(arg=None):
        exit(arg)

    def do_exit(self, arg=None):
        self.do_quit(arg)

if __name__ == "__main__":
    NAME = os.path.basename(sys.argv[0])

    if not hasattr(logging, 'NullHandler'):
        logging.NullHandler = NullHandler

    for sig in [signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT]:
        signal.signal(sig, sig_handler)

    parser = OptionParser()
    parser.add_option("-v", "--verbose", help="Debug messages sent to STDOUT", action="store_true")
    (options, args) = parser.parse_args()

    logger = logging.getLogger(NAME)
    logger.setLevel(logging.INFO)

    Dformatter = logging.Formatter('%(asctime)s %(message)s')
    Vformatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')

    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    console.setFormatter(Dformatter)

    logger.addHandler(console)

    cli = Cli(options.verbose)
    cli.cmdloop()
    exit()
