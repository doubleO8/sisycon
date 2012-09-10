#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import re
import sys
import subprocess

root_dir = "/filebase/incoming/wdtv/ftpext2.wdc.com"
root_out = "/mnt/speed/pepper-logs"
decrypt_command_template = 'openssl des3 -d -salt -in "%(source)s" -out "%(target)s.gz" -k "u;6tjp au04"'

def file_starts_with(filename, magic="Salted"):
    magic_length = len(magic)

    try:
        file_handle = open(filename, "r")
        data = file_handle.read(magic_length)
        file_handle.close()
        if data == magic:
            #print("%s starts with '%s'" % (filename, magic))
            return True
        else:
            #print("%s does not start with '%s' but %s" % (filename, magic, repr(data)))
            pass
    except Exception, e:
        print e
    return False

def mkdirp(target_dir):
    try:
        os.makedirs(target_dir)
    except Exception, e:
        if not os.path.isdir(target_dir):
            print e

for root, dirs, files in os.walk(root_dir):
    for filename in files:
        abs_filename = os.path.join(root, filename)
        if file_starts_with(abs_filename):
            target = abs_filename.replace(root_dir, root_out, 1)
            target_dir = os.path.dirname(target)
            mkdirp(target_dir)
            params = { 'source' : abs_filename, 'target' : target }
            try:
                subprocess.call( decrypt_command_template % params, shell=True)
            except Exception, e:
                print e
