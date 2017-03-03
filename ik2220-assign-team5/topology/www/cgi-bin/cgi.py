#!/usr/bin/python
import sys, os
from subprocess import call

print "Content-Type: text/html\n\n";

print "%s " %call("ifconfig")