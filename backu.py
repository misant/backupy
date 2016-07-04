#!/usr/bin/env python
# -*- coding: utf-8 -*-

from paramiko import SSHClient, AutoAddPolicy
from shutil import copyfile, move
from getpass import getpass
import os
import time
import datetime
import hashlib
import sys
import getopt

#import logging
#logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
#logging.debug('This is a log message.')

ssh = SSHClient()
mode = ''

def get_data(device_ip, work_dir):
    """Connects to remote RouterOS with device_ip using keys and runs runs "export verbose" to
    get actual configuration. Determines hostname and saves configuration to actual folder as work_dir/actual/hostname.cfg
    and to archive folder as workdir/cfg/hostname/timestamp.cfg
    If new config is same as already archived it is deleted.
    Also all files stored on RouterOS device are copied to workdir/files/hostname/
    """
    host = device_ip
    user = 'admin'
    port = 22
    actual_dir = work_dir + "actual/"

    if not os.path.exists(actual_dir):
        os.makedirs(actual_dir)


    ssh.set_missing_host_key_policy(AutoAddPolicy())
    remote_cmd = 'export verbose'

    try:
        time_stamp = time.strftime("%Y.%m.%d.%H-%M-%S")
        print datetime.datetime.now(), "Connecting.. " + host
        try:
            ssh.connect(hostname=host, username=user, timeout=3)
            ssh.get_transport().window_size = 3 * 1024 * 1024
            print datetime.datetime.now(), "Connected"

        except:
            print datetime.datetime.now(), "SSH connection failed"
        stdin, stdout, stderr = ssh.exec_command(remote_cmd, timeout=15)
        data = stdout.read() + stderr.read()


        if "user aaa" in data:
            print datetime.datetime.now(), "Config is OK!"
            file_tmp = open(work_dir + 'config.tmp', 'w')
            file_tmp.write(data)
            file_tmp.close()

            file_tmp = open(work_dir + 'config.tmp', 'r+')
            data = file_tmp.readlines()
            file_tmp.seek(0)
            for i in data:
                if not 'by RouterOS' in i:
                    file_tmp.write(i)
                    if 'set name=' in i:
                        hostname = i.split('=')
                        hostname = hostname[1]
                        hostname = hostname.rstrip()
                        print datetime.datetime.now(), "Device name from config = " + hostname
            file_tmp.truncate()
            file_tmp.close()
            copyfile (work_dir + 'config.tmp', actual_dir + hostname + '.cfg' )


            device_dir = work_dir + 'cfg/' + hostname + '/'
            if not os.path.exists(device_dir):
                os.makedirs(device_dir)
            move (work_dir + 'config.tmp', device_dir + time_stamp + '.cfg' )

            print datetime.datetime.now(), "Deduplicating configuration files"
            try:
                check_for_duplicates(device_dir)
                print datetime.datetime.now(), "Deduplication SUCCEED"
            except:
                print datetime.datetime.now(), "Deduplication FAILED"


            files_dir = work_dir + 'files/' + hostname + "/"
            if not os.path.exists(files_dir):
                os.makedirs(files_dir)

            print datetime.datetime.now(), "Transfering files..."


            try:
                ssh_copy_files (files_dir)
                print datetime.datetime.now(), "Transfering files SUCCESS"
            except:
                print datetime.datetime.now(), "Tanssfering files FAIL"



        else:
            print datetime.datetime.now(), "Config broken!"


        ssh.close()

    except:
        print datetime.datetime.now(), "Error connecting to host", host
    print datetime.datetime.now(), device_ip + " done.\n"
    return

def remote_cmd(device_ip,cmd):
    """Connects to remote RouterOS with device_ip using keys and runs runs "export verbose" to
    get actual configuration. Determines hostname and saves configuration to actual folder as work_dir/actual/hostname.cfg
    and to archive folder as workdir/cfg/hostname/timestamp.cfg
    If new config is same as already archived it is deleted.
    Also all files stored on RouterOS device are copied to workdir/files/hostname/
    """
    host = device_ip
    user = 'root'
    port = 22


    ssh.set_missing_host_key_policy(AutoAddPolicy())
#    remote_cmd = 'uptime'

    try:
        time_stamp = time.strftime("%Y.%m.%d.%H-%M-%S")
        print datetime.datetime.now(), "Connecting.. " + host
        try:
            ssh.connect(hostname=host, username=user, timeout=3)
            ssh.get_transport().window_size = 3 * 1024 * 1024
            print datetime.datetime.now(), "Connected"

        except:
            print datetime.datetime.now(), "SSH connection failed"
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=15)
        data = stdout.read() + stderr.read()

        print data
#       output = data.readlines()
#       for line in output:
#           print line

        ssh.close()

    except:
        print datetime.datetime.now(), "Error connecting to host", host
    print datetime.datetime.now(), device_ip + " done.\n"
    return

def ssh_key_transfer(ip, password, pub_key):
    """Connect to ip with password and put pub_key into authorized_keys"""
    try:
        key_file = open(pub_key, 'r')
        key = key_file.read().rstrip()
    except:
        print datetime.datetime.now(), "Cannot open %s" %("pub_key")
    cmd = 'umask 07; mkdir .ssh; echo "' + key + '" >> .ssh/authorized_keys'
    user = 'root'
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    time_stamp = time.strftime("%Y.%m.%d.%H-%M-%S")
    print datetime.datetime.now(), "Connecting.. " + ip
    try:
        ssh.connect(hostname=ip, username=user, password=password, timeout=3)
        ssh.get_transport().window_size = 3 * 1024 * 1024
        print datetime.datetime.now(), "Connected"

        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=15)
        data = stdout.read() + stderr.read()

        print data
        ssh.close()
    except:
        print datetime.datetime.now(), "SSH connection failed"
    print datetime.datetime.now(), ip + " done.\n"
    key_file.close()
    return


def ssh_copy_files(files_dir, remote_dir="/"):
    """Recursive copy of all files from remote_dir to files_dir"""
    sftp = ssh.open_sftp()
    remote_dirlist = []


    for i in sftp.listdir(remote_dir):
        lstatout=str(sftp.lstat(remote_dir + '/' + i)).split()[0]
        if 'd' in lstatout:
            remote_dirlist.append([i])

        else:
            sftp.get(remote_dir + i, files_dir + i)


    for found_dir in remote_dirlist:
        nfound_dir=''.join(found_dir)
        nfiles_dir = files_dir + nfound_dir + "/"
        if not os.path.exists(files_dir + nfound_dir):
            os.makedirs(files_dir + nfound_dir)
        ssh_copy_files (nfiles_dir, "/" + nfound_dir + "/")

    sftp.close
    return


def ssh_copy(ip, work_dir, password='some pass', remote_dir='/home/backup/'):
    """SSH copy from remote_dir to work_dir"""

    user = 'root'
    port = 22

    ssh.set_missing_host_key_policy(AutoAddPolicy())


    time_stamp = time.strftime("%Y.%m.%d.%H-%M-%S")
    print datetime.datetime.now(), "Connecting.. " + ip

    try:
        ssh.connect(hostname=ip, username=user, timeout=3, password=password)
        ssh.get_transport().window_size = 3 * 1024 * 1024
        print datetime.datetime.now(), "Connected"

        sftp = ssh.open_sftp()
        remote_dirlist = []

        for i in sftp.listdir(remote_dir):
            lstatout=str(sftp.lstat(remote_dir + '/' + i)).split()[0]
            if 'd' in lstatout:
                remote_dirlist.append([i])

            else:
                if ".sh" in i:          #transfer only tgz files
                    print datetime.datetime.now(), "Tranfserring %s:" %(i)
                    try:
                        sftp.get(remote_dir + i, work_dir + i, callback=print_totals)
                        print datetime.datetime.now(), "Transferring complete:", i
                    except:
                        print datetime.datetime.now(), "Transferring FAILED", i
        for found_dir in remote_dirlist:
            nfound_dir=''.join(found_dir)
            nfiles_dir = work_dir + nfound_dir + "/"
            if not os.path.exists(work_dir + nfound_dir):
                os.makedirs(work_dir + nfound_dir)
#               ssh_copy(nfiles_dir, "/" + nfound_dir + "/")  #need to adjust for recursion

        sftp.close
        ssh.close()
    except:
        print datetime.datetime.now(), "Can not connect %s via SSH" %(ip)

    return

def print_totals(transferred, to_be_transferred):
    if to_be_transferred > 1048576:
        print datetime.datetime.now(), "Transferred: {0}MB\t\tOut of: {1}MB\r".format((transferred / 1048576), (to_be_transferred / 1048576)),
        sys.stdout.flush()
    elif to_be_transferred > 1024:
        print datetime.datetime.now(), "Transferred: {0}KB\t\tOut of: {1}KB\r".format((transferred / 1024), (to_be_transferred / 1024)),
        sys.stdout.flush()
    else:
        print datetime.datetime.now(), "Transferred: {0}B\t\tOut of: {1}B\r".format(transferred, to_be_transferred),
        sys.stdout.flush()

    return

def chunk_reader(fobj, chunk_size=1024):
    """Generator that reads a file in chunks of bytes"""
    while True:
        chunk = fobj.read(chunk_size)
        if not chunk:
            return
        yield chunk

def check_for_duplicates(dpath, hash=hashlib.sha1):
    """Delete duplicate files in folder
    Copy pasted from http://stackoverflow.com/a/748908/6221971
    And changed to parse only one argument as path
    """
    hashes = {}
    for dirpath, dirnames, filenames in os.walk(dpath):
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            hashobj = hash()
            for chunk in chunk_reader(open(full_path, 'rb')):
                hashobj.update(chunk)
            file_id = (hashobj.digest(), os.path.getsize(full_path))
            duplicate = hashes.get(file_id, None)
            if duplicate:
                os.remove(full_path)
            else:
                hashes[file_id] = full_path
    return



class Usage(Exception):
    def __init__(self, msg):
        self.msg = "Usage:\
                    -t to transfer public key to remote host"


def main(argv=None):
    if argv is None:
        argv = sys.argv
        #default values
        work_dir = "/root/python/"
        ip_file = open(work_dir + "rb", 'r')
        mode = 'rb'
    try:
        try:
            opts, args = getopt.getopt(argv[1:], "btmhp:f:l:", ["help"])
        except getopt.error, msg:
             raise Usage(msg)

        #parse options
        for o, a in opts:
            if o in ("-h", "--help"):
                print "Usage:\n -t to transfer SSH key to remote host\n -p path to workdir\n -f path to file with ip addresses "
                sys.exit(0)
            if o in ("-p"):
                work_dir = a
                if not os.path.exists(work_dir):
                    os.makedirs(work_dir)
            if o in ("-f"):
                ip_file = open(a, 'r')
            if o in ("-m"):
                print "Mikrotik mode"
                mode = 'rb'
            if o in ("-l"):
                print "Linux mode"
                mode = 'pf'
                cmd = a
            if o in ("-t"):
                print "Transfer keys"
                mode = "kt"
            if o in ("-b"):
                print "psSense backup mode"
                mode = 'pb'

        ip_list = ip_file.readlines()
        for ip in ip_list:
            ip = ip.rstrip()
            if mode == 'rb':
                get_data(ip, work_dir)
            if mode == 'pf':
                remote_cmd(ip,cmd)
            if mode == "kt":
                password = getpass("Enter password for remote host %s:" %(ip))
                pub_key  = raw_input("Enter which public key to use:")
                if not os.path.exists(pub_key):
                    print "%s does not exist" %(pub_key)
                else:
                    ssh_key_transfer(ip,password,pub_key)
            if mode == 'pb':
#               password = getpass("Enter password for remote host %s:" %(ip))
                if not os.path.exists('/root/pf_backup/' + ip + '/'):
                    os.makedirs('/root/pf_backup/' + ip + '/')
                ssh_copy(ip, '/root/pf_backup/' + ip + '/')
            else:
                print "Mode option unselected", ip
        ip_file.close()


    except Usage, err:
        print >>sys.stderr, err.msg
        print >>sys.stderr, "for help use --help"
        return 2

if __name__ == "__main__":
    sys.exit(main())

