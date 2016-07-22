#!/usr/bin/env python
# -*- coding: utf-8 -*-

# import external modules
import paramiko
from paramiko import SSHClient, AutoAddPolicy
from shutil import copyfile, move
from multiprocessing import Pool
import os
import time
import datetime
import hashlib
import sys
import argparse
import socket

# variables used
ssh = SSHClient()


# import logging
# logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
# logging.debug('This is a log message.')


def open_ssh_session(ip, password="", user="root"):
    """Open SSH connection using password or key to ip"""
    flag = 1
    # Add key if not exist
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    print "\n", datetime.datetime.now(), "Connecting.. " + ip
    try:
        ssh.connect(hostname=ip, username=user, password=password, timeout=5)
        print datetime.datetime.now(), "%s connected" % ip
    except paramiko.AuthenticationException:
        print datetime.datetime.now(), "Authentication into %s FAILED" % ip
        flag = 0
    except paramiko.SSHException:
        print datetime.datetime.now(), "%s Negotiation FAILED" % ip
        flag = 0
    except socket.error:
        print datetime.datetime.now(), "Host %s is UNREACHABLE" % ip
        flag = 0
    except socket.timeout:
        print datetime.datetime.now(), "Connecting to host %s TIMEDOUT" % ip
        flag = 0
    if ssh.get_transport():
        ssh.get_transport().window_size = 3 * 1024 * 1024
    else:
        print datetime.datetime.now(), "%s SSH connection FAILED" % ip
    return flag


def close_ssh_session():
    """Close SSH connection"""
    ssh.close()
    print datetime.datetime.now(), "SSH connection closed"
    return


def ssh_cmd_exec(cmd):
    """Executes command on remote host and returns output as ssh_out"""
    try:
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=15)
        ssh_out = stdout.read() + stderr.read()
    except paramiko.SSHException:
        print datetime.datetime.now(), 'Executing "%s" FAILED' % cmd
        ssh_out = ""
    except socket.timeout:
        print datetime.datetime.now(), 'Executing "%s" TIMEDOUT' % cmd
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


def ssh_get_files(source_dir, target_dir, mask="", showprogress="", overwrite="no"):
    """Recursive copy of all files from source_dir to target_dir with wildmask filtering"""
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
                if overwrite != "yes":
                    if os.path.isfile(target_dir + i) and sftp.lstat(source_dir + i).st_size == os.lstat(
                                    target_dir + i).st_size:
                        if showprogress:
                            print datetime.datetime.now(), '%s is actual' % i
                        continue
                if showprogress:
                    print datetime.datetime.now(), "Transferring %s" % i,
                    sftp.get(source_dir + i, target_dir + i, callback=print_totals)
                    print datetime.datetime.now(), "%s - OK\t" % i
                else:
                    sftp.get(source_dir + i, target_dir + i)

    for found_dir in remote_dirlist:
        nfound_dir = ''.join(found_dir)
        new_target_dir = target_dir + nfound_dir + "/"
        if not os.path.exists(target_dir + nfound_dir):
            os.makedirs(target_dir + nfound_dir)
        ssh_get_files(source_dir + nfound_dir + "/", new_target_dir, mask, showprogress, overwrite)
    sftp.close()
    return


def print_totals(transferred, to_be_transferred):
    if to_be_transferred > 1048576:
        print datetime.datetime.now(), "Sent: \t{0}MB\t\t\tOut of: {1}MB\r".format((transferred / 1048576),
                                                                                   (to_be_transferred / 1048576)),
        sys.stdout.flush()
    elif to_be_transferred > 1024:
        print datetime.datetime.now(), "Sent: \t{0}KB\t\t\tOut of: {1}KB\r".format((transferred / 1024),
                                                                                   (to_be_transferred / 1024)),
        sys.stdout.flush()
    else:
        print datetime.datetime.now(), "Sent: \t{0}B\t\t\tOut of: {1}B\r".format(transferred, to_be_transferred),
        sys.stdout.flush()
    return


def ssh_key_transfer(ip, password, pub_key):
    """Connect to ip with password and put pub_key into authorized_keys"""
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    try:
        ssh.connect(hostname=ip, timeout=3)
        if ssh.get_transport():
            print datetime.datetime.now(), "%s is already have our key deployed" % ip
            close_ssh_session()
        return
    except:
        pass

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


def backup_ros(ip, target_dir, showprogress, overwrite):
    """Backup ROS config, delete duplicates, backup files"""
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
    log_file = open(target_dir + ip + '.log', 'a')
    sys.stdout = log_file

    if open_ssh_session(ip, user="admin"):
        config = get_ros_config()
    else:
        return
    if check_ros_config(config):
        hostname = get_ros_hostname(config)
        device_dir = target_dir + 'cfg/' + hostname + '/'
        clean_ros_config(target_dir, config)
        save_ros_config(target_dir, hostname)
        delete_duplicates(device_dir)
        try:
            ssh_get_files("/", target_dir + "files/" + hostname + '/', '', showprogress, overwrite)
            print datetime.datetime.now(), "Files transfer from %s SUCCESS" % ip
        except SSHError:
            print datetime.datetime.now(), "Files transfer from %s FAILED" % ip
    close_ssh_session()
    sys.stdout = sys.__stdout__
    log_file.close()
    return


def ros_helper(args):
    return backup_ros(*args)


def backup_nix(ip, password, source_dir, target_dir, showprogress, overwrite, mask=""):
    """Backup files with SFTP"""
    try:
        if open_ssh_session(ip, password):
            ssh_get_files(source_dir, target_dir, mask, showprogress, overwrite)
            close_ssh_session()
    except paramiko.AuthenticationException:
        print datetime.datetime.now(), "Authentication into %s FAILED" % ip
    return


def backup_pf(ip, password, source_dir, target_dir, showprogress, overwrite, mask=""):
    """Backup files with SFTP"""
    try:
        if open_ssh_session(ip, password):
            try:
                ssh_get_files(source_dir, target_dir, mask, showprogress, overwrite)
                ssh_cmd_exec("mkdir /home/backup/ok")
            except:
                print datetime.datetime.now(), "File transfer from %s FAILED" % ip
            close_ssh_session()
    except paramiko.AuthenticationException:
        print datetime.datetime.now(), "Authentication into %s FAILED" % ip
    return


def validate_ip(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        # legal
    except socket.error:
        # Not legal
        print datetime.datetime.now(), 'IP address "%s" is not valid, SKIPPED' % ip
        ip = ''
    return ip


def validate_path(path):
    if os.path.isabs(path):
        if not path.endswith('/'):
            path += '/'
    else:
        path = ''
    return path


class SSHError(Exception):
    pass


def usage():
    print 'Usage text information'
    return


# noinspection PyTypeChecker
def main():
    ip_list = []
    parser = argparse.ArgumentParser(description='Backup RouterOS of remote files with SSH and SFTP',
                                     epilog='Have a nice day!', formatter_class=argparse.RawTextHelpFormatter,
                                     add_help=False)
    parser.add_argument('--mode', help='		mode selection', choices=['mikrotik', 'sftp', 'pfsense', 'key'])
    hosts_list = parser.add_mutually_exclusive_group()
    hosts_list.add_argument('-i', '--ip', help='		ip address of remote host')
    hosts_list.add_argument('-a', '--addr', help='		file with ip address list')
    parser.add_argument('-p', '--passw', help='		password for remote host')
    parser.add_argument('-d', '--dest', help='		absolut path to destination folder for backup')
    parser.add_argument('-s', '--source', help='		absolute path to source folder for backup')
    parser.add_argument('-m', '--mask', help='		wildmask for files to copy')
    parser.add_argument('--key_path', help='		path to public key file')
    parser.add_argument('--multi', action="store_true", help='		enable if you want multiprocessing')
    parser.add_argument('--overwrite', action="store_true",
                        help='		if set all files will be overwrited without check\n')
    parser.add_argument('-v', '--verbose', action="store_true",
                        help='		verbose mode, show progress and extended output')
    parser.add_argument('-h', '--help', action="store_true", help='		show this help message and exit')

    args = parser.parse_args()

    ros = False
    nix = False
    pf_sense = False
    key = False

    if args.mode == 'mikrotik':
        ros = True
    if args.mode == 'sftp':
        nix = True
    if args.mode == 'pfsense':
        pf_sense = True
    if args.mode == 'key':
        key = True

    # args validation
    if nix or ros or key:
        if not args.ip and not args.addr:
            parser.error('You need to set --ip or --addr')

    if ros:
        if not args.dest:
            parser.error('The --ros argument requires --dest')

    if nix:
        if not args.source or not args.dest:
            parser.error('The --nix argument requires: --source and --dest')

    if key:
        if not args.key_path or not args.passw:
            parser.error('The --key argument requires both --key_path and --passw')

    if not args.mask:
        args.mask = ""

    if args.source:
        args.source = validate_path(args.source)
        if not args.source:
            parser.error('--source is not valid path')

    if args.dest:
        args.dest = validate_path(args.dest)
        if not args.dest:
            parser.error('--dest is not valid path')

    if args.overwrite:
        overwrite = "yes"
    else:
        overwrite = ''

    # parse options
    if args.help:
        parser.print_help()
        sys.exit(0)

    if args.verbose:
        showprogress = 'yes'
    else:
        showprogress = ''

    if args.addr:
        if os.path.exists(args.addr):
            args.addr = open(args.addr, 'r')
            ip_list = args.addr.readlines()
            args.addr.close()
        else:
            parser.error('Address list file "%s" does not exist' % args.addr)

    if args.ip:
        ip = validate_ip(args.ip)
        ip_list = [[ip]]

    if ros:
        ip_list_validated = []
        # multi process version
        if args.multi:
            for ip in ip_list:
                ip = ''.join(ip)
                ip = ip.rstrip()
                ip = validate_ip(ip)
                if ip:
                    ip_list_validated.append(ip)

            job_args = [(ip, args.dest, showprogress, overwrite) for ip in ip_list_validated]
            pool = Pool(len(ip_list))
            pool.map(ros_helper, job_args, 1)
            pool.close()
            pool.join()
            sys.exit(0)
        # single process version
        else:
            for ip in ip_list:
                ip = ''.join(ip)
                ip = ip.rstrip()
                ip = validate_ip(ip)
                if ip:
                    backup_ros(ip, args.dest, showprogress, overwrite)
            sys.exit(0)

    if nix:
        for ip in ip_list:
            ip = ''.join(ip)
            ip = ip.rstrip()
            ip = validate_ip(ip)
            if ip:
                if args.ip:
                    backup_nix(ip, args.passw, args.source, args.dest, showprogress, overwrite, args.mask)
                else:
                    backup_nix(ip, args.passw, args.source, args.dest + ip + '/', showprogress, overwrite, args.mask)
        sys.exit(0)

    if pf_sense:
        for ip in ip_list:
            ip = ''.join(ip)
            ip = ip.rstrip()
            ip = validate_ip(ip)
            if ip:
                backup_pf(ip, args.passw, args.source, args.dest + ip + '/', showprogress, overwrite, args.mask)
        sys.exit(0)

    if key:
        for ip in ip_list:
            ip = ''.join(ip)
            ip = ip.rstrip()
            ip = validate_ip(ip)
            if ip:
                ssh_key_transfer(ip, args.passw, args.key_path)
        sys.exit(0)

    parser.print_usage()
    print '--help for help'
if __name__ == "__main__":
    sys.exit(main())

