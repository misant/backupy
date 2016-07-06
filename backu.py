#!/usr/bin/env python
# -*- coding: utf-8 -*-

# import external modules
from paramiko import SSHClient, AutoAddPolicy
from shutil import copyfile, move
from getpass import getpass
import os
import time
import datetime
import hashlib
import sys
import argparse

# variables used
ssh = SSHClient()
mode = ''


# import logging
# logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
# logging.debug('This is a log message.')


def open_ssh_session(ip, password="", user="root"):
    """Open SSH connection using password or key to ip"""
# Add key if not exist
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    print datetime.datetime.now(), "Connecting.. " + ip
# If password passed try to connect with it
    if password:
        ssh.connect(hostname=ip, username=user, password=password, timeout=3)
# If not try to connect with key
    else:
        ssh.connect(hostname=ip, username=user, timeout=3)
    if ssh.get_transport():
        ssh.get_transport().window_size = 3 * 1024 * 1024
        print datetime.datetime.now(), "%s connected" % ip
    else:
        print datetime.datetime.now(), "%s SSH connection FAILED" % ip
    return


def close_ssh_session():
    """Close SSH connection"""
    ssh.close()
    print datetime.datetime.now(), "SSH connection closed"
    return


def ssh_cmd_exec(cmd):
    """Executes command on remote host"""
    try:
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=15)
        ssh_out = stdout.read() + stderr.read()
    except paramiko.SSHException:
        print datetime.datetime.now(), 'Executing "%s" FAILED' % cmd
        ssh_out = ""
    return ssh_out


def get_ros_config():
    """Connects to remote RouterOS with device_ip using keys and runs runs "export verbose" to
     get actual configuration. Determines hostname and saves configuration to actual folder
     as work_dir/actual/hostname.cfg
     and to archive folder as workdir/cfg/hostname/timestamp.cfg
     If new config is same as already archived it is deleted.
     Also all files stored on RouterOS device are copied to workdir/files/hostname/
     """
    try:
        ros_config = ssh_cmd_exec("export verbose")
        print datetime.datetime.now(), "RouterOS configuration downloaded"
    except SSHError:
        print datetime.datetime.now(), "FAILED getting RouterOS configuration"
        ros_config = ""
    return ros_config


def check_ros_config(ros_config):
    """Check if ROS config was downloaded till last section"""
    if "user aaa" in ros_config:
        print datetime.datetime.now(), "Router OS configurations is OK"
        check = True
    else:
        print datetime.datetime.now(), "Router OS configurations is BROKEN!"
        check = False
    return check


def get_ros_hostname(ros_config):
    """Determine hostname from ROS config"""
    hostname = "unknown"
    for line in ros_config.splitlines():
        if 'set name=' in line:
            hostname = line.split('=')
            hostname = hostname[1]
            hostname = hostname.rstrip()
    print datetime.datetime.now(), "Device name from config = " + hostname
    return hostname


def clean_ros_config(target_dir, ros_config):
    """Save ROS config to config.tmp without timestamp line"""
    file_tmp = open(target_dir + 'config.tmp', 'w')
    file_tmp.write(ros_config)
    file_tmp.close()

    file_tmp = open(target_dir + 'config.tmp', 'r+')
    ros_config = file_tmp.readlines()
    file_tmp.seek(0)

    for line in ros_config:
        if 'by RouterOS' not in line:
            file_tmp.write(line)

    file_tmp.truncate()
    file_tmp.close()
    return


def save_ros_config(target_dir, hostname):
    """Save ROS config to target dir"""
    # Save actual config
    actual_dir = target_dir + "actual/"
    if not os.path.exists(actual_dir):
        os.makedirs(actual_dir)
    copyfile(target_dir + 'config.tmp', actual_dir + hostname + '.cfg')
    # Save historical config
    device_dir = target_dir + 'cfg/' + hostname + '/'
    if not os.path.exists(device_dir):
        os.makedirs(device_dir)
    time_stamp = time.strftime("%Y.%m.%d.%H-%M-%S")
    move(target_dir + 'config.tmp', device_dir + time_stamp + '.cfg')
    return


def chunk_reader(fobj, chunk_size=1024):
    """Generator that reads a file in chunks of bytes"""
    while True:
        chunk = fobj.read(chunk_size)
        if not chunk:
            return
        yield chunk


def delete_duplicates(dpath, hash=hashlib.sha1):
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


def ssh_get_files(source_dir, target_dir, mask="", showprogress="y"):
    """Recursive copy of all files from remote_dir to files_dir"""
    sftp = ssh.open_sftp()
    remote_dirlist = []

    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    for i in sftp.listdir(source_dir):
        lstatout = str(sftp.lstat(source_dir + i)).split()[0]
        if 'd' in lstatout:
            remote_dirlist.append([i])
        else:
            if mask in i:
                print datetime.datetime.now(), "Transferring %s" % i
                if showprogress:
                    sftp.get(source_dir + i, target_dir + i, callback=print_totals)
                else:
                    sftp.get(source_dir + i, target_dir + i)
                print datetime.datetime.now(), "Transferring %s complete" % i

    for found_dir in remote_dirlist:
        nfound_dir = ''.join(found_dir)
        new_target_dir = target_dir + nfound_dir + "/"
        if not os.path.exists(target_dir + nfound_dir):
            os.makedirs(target_dir + nfound_dir)
        ssh_get_files(source_dir + nfound_dir + "/", new_target_dir, mask)
    sftp.close()
    return


def print_totals(transferred, to_be_transferred):
    if to_be_transferred > 1048576:
        print datetime.datetime.now(), "Transferred: {0}MB\t\tOut of: {1}MB\r".format((transferred / 1048576),
                                                                                      (to_be_transferred / 1048576)),
        sys.stdout.flush()
    elif to_be_transferred > 1024:
        print datetime.datetime.now(), "Transferred: {0}KB\t\tOut of: {1}KB\r".format((transferred / 1024),
                                                                                      (to_be_transferred / 1024)),
        sys.stdout.flush()
    else:
        print datetime.datetime.now(), "Transferred: {0}B\t\tOut of: {1}B\r".format(transferred, to_be_transferred),
        sys.stdout.flush()
    return


def ssh_key_transfer(ip, password, pub_key):
    """Connect to ip with password and put pub_key into authorized_keys"""
    try:
        key_file = open(pub_key, 'r')
        key = key_file.read().rstrip()
        key_file.close()
        cmd = 'umask 07; mkdir .ssh; echo "' + key + '" >> .ssh/authorized_keys'

        try:
            open_ssh_session(ip, password)
            ssh_cmd_exec(cmd)
            close_ssh_session()
            print datetime.datetime.now(), ip + " SSH key deployed.\n"
        except SSHError:
            print datetime.datetime.now(), ip + " SSH key deployment FAILED.\n"

    except IOError:
        print datetime.datetime.now(), "Cannot open %s" % pub_key

    return


def backup_ros(ip, target_dir):
    """Backup ROS config, delete duplicates, backup files"""
    open_ssh_session(ip, user="admin")
    config = get_ros_config()
    if check_ros_config(config):
        if not os.path.exists(target_dir):
            os.makedirs(target_dir)
        hostname = get_ros_hostname(config)
        device_dir = target_dir + 'cfg/' + hostname + '/'
        clean_ros_config(target_dir, config)
        save_ros_config(target_dir, hostname)
        delete_duplicates(device_dir)
        ssh_get_files("/", target_dir + "files/" + hostname + '/')
    close_ssh_session()
    return


def backup_nix(ip, password, source_dir, target_dir, mask=""):
    """Backup files with SFTP"""
    open_ssh_session(ip, password)
    ssh_get_files(source_dir, target_dir, mask)
    close_ssh_session()
    return


class SSHError(Exception):
    pass


def usage():
    print 'Usage text information'
    return


def main():

    parser = argparse.ArgumentParser(description='Backup RouterOS of remote files with SSH and SFTP',
                                     epilog='Have a nice day!')
    smode = parser.add_mutually_exclusive_group()
    smode.add_argument('-r', '--ros', action="store_true", help='backup RouterOS')
    smode.add_argument('-x', '--nix', action="store_true", help='transfer files from linux with SFTP')
    smode.add_argument('-k', '--key', action="store_true", help='deploy SSH key to linux host')
    hosts_list = parser.add_mutually_exclusive_group()
    hosts_list.add_argument('-i', '--ip', help='ip address of remote host')
    hosts_list.add_argument('-a', '--addr', help='file with ip address list')
    parser.add_argument('-p', '--passw', help='password for remote host')
    parser.add_argument('-d', '--dest', help='destination folder for backup')
    parser.add_argument('-s', '--source', help='source folder for backup')
    parser.add_argument('-m', '--mask', help='wildmask for files to copy')
    parser.add_argument('--key_path', help='path to public key')

    args = parser.parse_args()

    # args validation
    if args.ros:
        if not args.dest:
            parser.error('The --ros argument requires --dest')

    if args.nix:
        if not args.source and not args.dest:
            parser.error('The --nix argument requires: --ip or --addr,  --source and --dest')

    if args.nix or args.ros or args.key:
        if not args.ip and not args.addr:
            parser.error('You need to set -ip or -addr')

    if args.key:
        if not args.key_path or not args.passw:
            parser.error('The --key argument requires both --key_path and --passw')

    if not args.mask:
        args.mask = ""

    # parse options
    if args.addr:
        args.addr = open(args.addr, 'r')
        ip_list = args.addr.readlines()
        args.addr.close()

    if args.ip:
        ip_list = []
        ip_list.append([args.ip])

    if args.ros:
        for ip in ip_list:
            ip = ''.join(ip)
            ip = ip.rstrip()
            backup_ros(ip, args.dest)
        sys.exit(0)

    if args.nix:
        for ip in ip_list:
            ip = ''.join(ip)
            ip = ip.rstrip()
            backup_nix(ip, args.passw, args.source, args.dest, args.mask)
        sys.exit(0)

    if args.key:
        for ip in ip_list:
            ip = ''.join(ip)
            ip = ip.rstrip()
            ssh_key_transfer(ip, args.passw, args.key_path)
        sys.exit(0)

if __name__ == "__main__":
    sys.exit(main())
