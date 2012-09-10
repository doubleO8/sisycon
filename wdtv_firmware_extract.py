#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
tool to handle WD Live SMP/Hub firmware releases.

Extracts zip files, scans for filesystem using binwalk, extracts these filesystems
and merges them into a directory. Creates a git repository too.
"""
import os
import re
import sys
import subprocess
import datetime
import pprint
import glob
import zipfile
import hashlib
import shutil
import tempfile
from optparse import OptionParser, OptionGroup

# directory where firmware contents will be extracted 
# (a subdirectory will be created for each version tho)
working_dir_root = '/mnt/speed'

# git tracker repository
git_tracker = os.path.join(working_dir_root, "the_branched_tracker")

# directory where binwalk outputs are stored
log_dir = '/filebase/incoming/binwalks'

# directory in which the zip files containing the firmware reside
zip_dump_dir = '/filebase/incoming/dump'

# template for naming scheme
extract_target_dir_template = os.path.join(working_dir_root, "extracted/%s/%s")

#: RegExp to match a firmware ZIP filename
firmware_zip_regexp = re.compile(r'.*?(livegen3|livehub).*?(\d+)[_\.](\d+)[_\.](\d+).*?\.zip', re.I)

#: RegExp to match a firmware pkg filename
firmware_pkg_regexp = re.compile(r'.*?(livegen3|livehub).*?(\d+)[_\.](\d+)[_\.](\d+)\.pkg', re.I)

#: RegExp to match a directory named after a version (e.g. /bla/1.2.3/bli/blu )
version_by_dirname_regexp = re.compile(r'.*?\/(\d+)\.(\d+)\.(\d+)\/?.*?', re.I)

#: RegExp to match a filesystem entry in binwalk output
fs_regexp = re.compile(r'^(\d+)\s+0x[A-Fa-f\d]+\s+(CramFS|Squashfs).*?size(:|) (\d+) (bytes|).*?$')

#: RegExp to match a version key/value pair
ver_kv_regexp = re.compile(r'^(.*?)\s*=\'(.*?)\'$')
#: RegExp to match an exported bash key/value pair
bash_kv_regexp = re.compile(r'^export\s*(.*?)\s*=(.*?)$')
#: RegExp to match a version string
version_regexp = re.compile(r'^(\d+)[^\w\d](\d+)[^\w\d](\d+)$')
#: RegExp to match a filename containing a checksum
checksum_file_regexp = re.compile(r'^([\w\d]{32})\s*(.*?)$')

def format_version(v_branch, v_major=0, v_minor=0):
    """
    Format given version information.
    Version may be defined using *v_branch*, *v_major* and *v_minor*.
    *v_branch* may be a tuple containing the three values.
    """
    if isinstance(v_branch, list):
        (v_branch, v_major, v_minor) = v_branch
    return "%02d.%02d.%02d" % (v_branch, v_major, v_minor)

def get_version(raw_version=None, as_dict=False, as_tuple=False):
    """
    Try to parse version informations using *raw_version* as source.
    Returns either a string, a ``dict()`` (in case *as_dict* is set)
    or a ``tuple()`` (with *as_tuple* being set).

    Default value: Version ``0.0.0``.
    """
    try:
        version_matcher = version_regexp.match(raw_version)
    except TypeError:
        version_matcher = None
    if not version_matcher:
        (v_branch, v_major, v_minor) = (0, 0, 0)
    else:
        (v_branch, v_major, v_minor) = [int(v) for v in version_matcher.groups()]

    if as_dict:
        return {'a' : v_branch, 'b' : v_major, 'c' : v_minor}
    if as_tuple:
        return (v_branch, v_major, v_minor)
    return format_version(v_branch, v_major, v_minor)

def get_version_information(file_reader):
    """
    Read a key/value defined version from file object *file_reader* using
    regular expression *ver_kv_regexp*.

    Default value: Version ``0.0.0``.
    """
    version_information = dict()

    for line in file_reader.readlines():
        matched = ver_kv_regexp.match(line.strip())
        if matched:
            (key, value) = matched.groups()
            version_information[key] = value

    file_reader.close()

    try:
        version_information['VERSION'] = get_version(version_information['VERSION'])
    except KeyError:
        version_information['VERSION'] = get_version()

    return version_information

def get_build_information(file_reader):
    """
    Read a key/value defined build version from file object *file_reader* using
    regular expression *bash_kv_regexp*.

    Default value: Version ``0.0.0``.
    """
    build_information = dict()

    for line in file_reader.readlines():
        matched = bash_kv_regexp.match(line.strip())
        if matched:
            (key, value) = matched.groups()
            build_information[key] = value

    file_reader.close()

    try:
        build_information['SYSCONF_BUILD_VERSION'] = get_version(build_information['SYSCONF_BUILD_VERSION'])
    except KeyError:
        build_information['SYSCONF_BUILD_VERSION'] = get_version()

    try:
        build_information['SYSCONF_BUILD_DATE'] = datetime.datetime.strptime(build_information['SYSCONF_BUILD_DATE'], "%Y.%m.%d-%H%M")
    except KeyError:
        try:
            build_information['SYSCONF_BUILD_DATE'] = release_mapping[build_information['SYSCONF_BUILD_VERSION']]
        except KeyError:
            build_information['SYSCONF_BUILD_DATE'] = datetime.datetime.strptime("1970-01-01", "%Y-%m-%d")

    return build_information

def mkdirp(target_dir):
    """
    Create *target_dir* in a similar manner ``mkdir -p`` would do.
    """
    try:
        os.makedirs(target_dir)
    except Exception, e:
        if not os.path.isdir(target_dir):
            print e

def get_checksum(source_filename, buffer_size=16384):
    """
    Computes the checksum for *source_filename* using a read buffer of
    *buffer_size* bytes. Returns the hex representation of a MD5 sum.
    """
    checksum = hashlib.md5()
    file_input = open(source_filename, "r")

    data = file_input.read(buffer_size)
    while len(data) > 0:
        checksum.update(data)
        data = file_input.read(buffer_size)

    file_input.close()
    return checksum.hexdigest()

def extract_from_zip(zip_object, source_filename, target_dir,
                    target_filename=None, may_overwrite=True, buffer_size=4096):
    """
    Extracts file *source_filename* from zip archive *zip_object* to 
    *target_dir*. The used target filename may be given (*target_file*)
    otherwise the basename of *source_filename* is used.
    Returns a tuple containing the used (absolute) path for the target filename
    and the hex representation of its MD5 checksum.
    """
    checksum = hashlib.md5()
    file_input = zip_object.open(source_filename, "r")
    do_write = True

    if target_filename == None:
        target_filename = os.path.join(target_dir, source_filename)
    else:
        target_filename = os.path.join(target_dir, target_filename)

    if os.path.exists(target_filename):
        print "Existing target '%s' !" % target_filename
        if not may_overwrite:
            do_write = False

    if do_write:
        file_output = open(target_filename, "w")

    data = file_input.read(buffer_size)
    while len(data) > 0:
        checksum.update(data)
        if do_write:
            file_output.write(data)
        data = file_input.read(buffer_size)

    file_input.close()
    if do_write:
        file_output.close()
    return (target_filename, checksum.hexdigest())

def binwalk_file(filename, checksum, force=False):
    """
    Runs the ``binwalk`` tool on file named *filename* and writes its output
    to ``<checksum>.binwalk.log``.
    If the file ``<checksum>.binwalk.log`` is already existing and *force* set
    to True it will be overwritten. Otherwise the existing file is read and
    its output is returned.
    Thus the time intensive task of running ``binwalk`` needs to be done only
    once.
    """
    mkdirp(log_dir)
    info_file = os.path.join(log_dir, "%s.binwalk.log" % checksum)

    if os.path.isfile(info_file):
        msg = "  +++ Existing binwalk information file: %s" % info_file
        if not force:
            #print msg
            file_handle = open(info_file, "r")
            content = file_handle.read()
            file_handle.close()
            # return cached content
            return content
        print msg + " (will be overwritten as requested)"

    output = subprocess.check_output(["binwalk", filename])
    file_handle = open(info_file, "w")
    file_handle.write(output)
    file_handle.close()
    return output

def binwalk_parse(output):
    """
    Parse filesystem informations out of ``binwalk`` output *output* using
    regular expression *fs_regexp*.
    """
    bw_information = []
    for line in output.split("\n"):
        matcher = fs_regexp.match(line)
        if matcher:
            (skip, fs_type, junk, fs_size) = matcher.groups()[:-1]
            #print "skip=%s type=%s size=%s bytes" % (skip, fs_type, fs_size)
            bw_information.append( (fs_type, skip, fs_size) )
    return bw_information

def dd_extract(source, target, count, skip=0, bs=1):
    """
    Run ``dd`` on *source* saving its contents to *target*.
    *count*, *skip* and *bs* parameters define which parts of *source* are to
    be copied.
    """
    cmd = '%s if="%s" of="%s" bs=%d skip=%d count=%d' % ('dd', source, target, bs, skip, count)
    subprocess.call(cmd, shell=True)

def read_checksum_index(path, index_files=["md5sums", "md5sums.txt"]):
    """
    Read checksum files (candidates being defined by *index_files*) stored 
    in *path*.
    Returns a { checksum : filename } ``dict()``.
    """
    checksums = []

    for index_file in index_files:
        try:
            file_handle = open(os.path.join(path, index_file), "r")
            for line in file_handle.readlines():
                matched = checksum_file_regexp.match(line)
                if matched:
                    (checksum, filename) = matched.groups()
                    abs_filename = os.path.join(path, filename)
                    if os.path.isfile(abs_filename):
                        checksums.append( (checksum, filename) )
        except Exception, e:
            #print e
            pass

    checksum_dict = {}
    for (checksum, filename) in checksums:
        checksum_dict[filename] = checksum
    return checksum_dict

def add_checksum_index(path, filename, checksum, index_file = "md5sums"):
    """
    Append checksum of *filename* to index file *index_file* stored 
    in *path*.
    """
    file_handle = open(os.path.join(path, index_file), "a")
    file_handle.write("%s %s\n" % (checksum, os.path.basename(filename)))
    file_handle.close()

def unsquashfs(filename, rename_dir=None, pwd=None):
    """
    Run ``unsquashfs`` on *filename* to extract its contents.
    Returns the path of the created directory.
    Existing 'squashfs-root' directories will be removed first.
    ``sudo`` is being used to allow renaming of directories containing device
    files.
    """
    resulting_dir = os.path.join(os.path.dirname(filename), "squashfs-root")

    if os.path.isdir(resulting_dir):
        shutil.rmtree(resulting_dir)

    if not pwd:
        pwd = os.path.dirname(filename)
    os.chdir(pwd)

    cmd = '%s -n "%s"' % ('unsquashfs', filename)
    subprocess.call(cmd, shell=True)

    if not os.path.isdir(resulting_dir):
        raise IOError("Missing resulting dir '%s' !" % resulting_dir)

    if rename_dir:
        mkdirp(rename_dir)
        cmd = 'sudo rsync -a "%s/" "%s"' % (resulting_dir, rename_dir)
        #print cmd
        subprocess.call(cmd, shell=True)
        shutil.rmtree(resulting_dir)
        resulting_dir = rename_dir
    return resulting_dir

#: Firmware release mapping for build not containing a build date information.
release_mapping = {
    get_version("2.4.13") : datetime.datetime.strptime("2011-03-13", "%Y-%m-%d"),
    get_version("2.5.8")  : datetime.datetime.strptime("2011-04-12", "%Y-%m-%d"),
    get_version("2.6.10") : datetime.datetime.strptime("2011-05-16", "%Y-%m-%d"),
    get_version("2.7.17") : datetime.datetime.strptime("2011-08-01", "%Y-%m-%d"),
    get_version("2.8.13") : datetime.datetime.strptime("2011-10-05", "%Y-%m-%d"),
}

def scan_for_build_informations(root_dir=None, candidates=None, device="unknown"):
    """
    Scan *root*_dir* for files defined by *candidates* 
    (defaulting to ``*/*/*/sysconfig`` if not set). Any found file is being
    parsed for build informations using regular expression *bash_kv_regexp*.
    *device* is used as name for the current device.
    Returns a ``dict()`` of gathered build informations.
    """
    builds = dict()
    
    if not candidates and root_dir:
        candidates = glob.glob(os.path.join(root_dir, "*/*/*/sysconfig"))
    elif root_dir and not candidates:
        candidates = list()
        for root, dirs, files in os.walk(root_dir):
            for filename in files:
                if filename != "sysconfig":
                    continue
                candidates.append(os.path.join(root, filename))

    for filename in candidates:
        build_information = dict()
        root = os.path.dirname(filename)
        file_reader = open(filename, "r")

        for line in file_reader.readlines():
            matched = bash_kv_regexp.match(line.strip())
            (key, value) = matched.groups()
            build_information[key] = value

        file_reader.close()
        
        build_information['source_root'] = root
        build_information['device'] = device
        build_information['educated_guess'] = False

        try:
            build_information['SYSCONF_BUILD_VERSION'] = get_version(build_information['SYSCONF_BUILD_VERSION'])
        except KeyError:
            matcher = version_by_dirname_regexp.match(build_information['source_root'])
            if matcher:
                build_information['SYSCONF_BUILD_VERSION'] = get_version('.'.join(matcher.groups()))
            else:
                build_information['SYSCONF_BUILD_VERSION'] = get_version()

        try:
            build_information['SYSCONF_BUILD_DATE'] = datetime.datetime.strptime(build_information['SYSCONF_BUILD_DATE'], "%Y.%m.%d-%H%M")
        except KeyError:
            build_information['educated_guess'] = True
            try:
                build_information['SYSCONF_BUILD_DATE'] = release_mapping[build_information['SYSCONF_BUILD_VERSION']]
            except KeyError:
                build_information['SYSCONF_BUILD_DATE'] = datetime.datetime.strptime("1970-01-01", "%Y-%m-%d")

        
        dict_key = "%s.%s.%s" % (build_information['SYSCONF_BUILD_DATE'].strftime("%Y-%m-%d_%H%M"), build_information['SYSCONF_BUILD_VERSION'], device)
        #dict_key = build_information['SYSCONF_BUILD_VERSION']
        builds[dict_key] = build_information
    return builds

def scan_for_firmware_images(root_dir):
    """
    Scans *root_dir* for firmware images.
    Currently zip and pkg files are supported.
    Returns a ``dict()`` containing { device : filename,version,image_type }
    informations.
    """
    fw_mapping = dict()

    for root, dirs, files in os.walk(root_dir):
        for filename in files:
            matcher = firmware_zip_regexp.match(filename)
            if matcher:
                device = 'wdtv' + matcher.group(1).lower()
                version = format_version([int(v) for v in matcher.groups()[1:]])
                image_type = "zip"
            else:
                matcher2 = firmware_pkg_regexp.match(filename)
                if matcher2:
                    device = 'wdtv' + matcher2.group(1).lower()
                    version = format_version([int(v) for v in matcher2.groups()[1:]])
                    image_type = "pkg"
                else:
                    continue

            fw_info = { 'filename' : os.path.join(root, filename),
                        'version' : version,
                        'device' : device,
                        'image_type' : image_type
            }
            
            try:
                fw_mapping[device][version] = fw_info
            except KeyError:
                fw_mapping[device] = {}
                fw_mapping[device][version] = fw_info
                    
    return fw_mapping

def dump_fs_image(vinfo, source_file, checksum, delete_after=True, may_overwrite=False):
    """
    Extracts firmware image from *source_file* using *vinfo*, *checksum* for
    further informations. Deletes *source_file* and overwrites files if
    *delete_after* or *may_overwrite* is set accordingly.
    """
    bw_output = binwalk_file(source_file, checksum)
    target_dir = os.path.dirname(source_file)
    source_bn = os.path.basename(source_file)
    dump_info = {}

    try:
        if source_bn == vinfo['LOCATION']:
            image_trunk = "root"
    except KeyError:
        pass

    try:
        if source_bn == os.path.basename(vinfo['PKG_LOCATION']):
            image_trunk = "root"
    except KeyError:
        pass

    try:
        if source_bn == vinfo['ROOTFS2']:
            image_trunk = "opt"
    except KeyError:
        pass

    for (fs_type, skip, fs_size) in binwalk_parse(bw_output):
        skip = int(skip)
        fs_size = int(fs_size)
        fs_type = fs_type.lower()
        target_filename = "%s.%s.image" % (image_trunk, fs_type)
        target = os.path.join(target_dir, target_filename)
        
        if not os.path.isfile(target) or may_overwrite:
            dd_extract(source_file, target, count=fs_size, skip=skip)
        dump_info[image_trunk] = { 'fs_type' : fs_type, 'source' : target, 'image_type' : image_trunk } 

    if delete_after:
        os.unlink(source_file)

    return dump_info

def extract_images(image_parts):
    """
    Extracts firmware image parts *image_parts*.
    Uses ``sudo`` for calling binaries if needed.
    """
    image_list = []

    try:
        image_list.append(image_parts['root'])
    except KeyError:
        pprint.pprint(image_parts)
        raise

    try:
        image_list.append(image_parts['opt'])
    except KeyError:
        pass

    for image in image_list:
        fs_type = image['fs_type']
        source = image['source']
        image_type = image['image_type']
        target_root = os.path.dirname(source)
        
        if image_type == 'root':
            target_dir = os.path.join(target_root, "root")
        elif image_type == 'opt':
            target_dir = os.path.join(target_root, "root/opt")
        else:
            raise ValueError("unknown image_type: %s" % image_type)

        pprint.pprint(image)
        if fs_type == 'cramfs':
            mkdirp(target_dir)
            tmp = tempfile.mkdtemp(suffix='image', prefix='cramfs', dir=target_root)
            subprocess.call('sudo mount "%s" "%s"' % (source, tmp), shell=True)
            subprocess.call('sudo rsync -a "%s/" "%s"' % (tmp, target_dir), shell=True)
            subprocess.call('sudo chmod -R a+r "%s"' % target_dir, shell=True)
            subprocess.call('sudo find "%s" -type d -exec chmod a+rx {} \;' % target_dir, shell=True)
            subprocess.call('sudo umount "%s"' % tmp, shell=True)
            shutil.rmtree(tmp)
        elif fs_type == 'squashfs':
            unsquashfs(source, rename_dir=target_dir)

def work_firmwares(firmwares, may_overwrite=False):
    """
    Extracts firmwares *firmwares*. Overwrites resulting image files
    if *may_overwrite* is set.
    """
    for device in available_firmwares:
        for version in sorted(available_firmwares[device]):
            current = available_firmwares[device][version]
            image_type = current['image_type']
            target_dir = extract_target_dir_template % (device, version)
            checksums = read_checksum_index(target_dir)

            print("%(version)-20s %(device)-15s : %(filename)s" % current)

            if image_type == 'zip':
                zip_object = zipfile.ZipFile(available_firmwares[device][version]['filename'])
                build_information_file = device + ".ver"
                file_reader = zip_object.open(build_information_file)
                vinfo = get_version_information(file_reader)
                image_files = [ vinfo["LOCATION"] ]
                try:
                    rootfs2 = vinfo["ROOTFS2"].strip()
                    if rootfs2:
                        image_files.append(rootfs2)
                except KeyError:
                    pprint.pprint(vinfo)
                    pass
            elif image_type == 'pkg':
                vinfo = {'PKG_LOCATION' : current['filename']}
                image_files = [ current['filename'] ]
            else:
                raise ValueError("unknown image_type '%s'" % image_type)


            image_parts = {}
            
            for source_filename in image_files:
                source_filename = os.path.basename(source_filename)
                target_filename = os.path.join(target_dir, source_filename)
                
                #print " %s" % target_filename
                mkdirp(target_dir)

                try:
                    checksum = checksums[source_filename]
                    print "  +++ Known checksum .. %s" % checksum
                except KeyError, ker:
                    # print "  !!! Missing checksum .. %s" % source_filename

                    if image_type == 'zip':
                        (target, checksum) = extract_from_zip(zip_object, 
                                source_filename=source_filename, 
                                target_dir=target_dir, 
                                target_filename=target_filename, 
                                may_overwrite=may_overwrite)
                        #print "%s : %s" % (target_filename, checksum)
                    elif image_type == 'pkg':
                        if not os.path.isfile(target_filename) or may_overwrite:
                            shutil.copy(current['filename'], target_filename)
                            checksum = get_checksum(target_filename)

                    add_checksum_index(target_dir, source_filename, checksum)
                        
                dump_info = dump_fs_image(vinfo, 
                                            target_filename,
                                            checksum, 
                                            may_overwrite=may_overwrite)
                for key in dump_info:
                    image_parts[key] = dump_info[key]

            try:
                extract_images(image_parts)
            except Exception, e:
                print e
                pprint.pprint(vinfo)
                pprint.pprint(image_parts)
                print("%(version)-20s %(device)-15s : %(filename)s" % current)
            #os.unlink(current['filename'])
        print ""

def build_git_tracker(builds, tracker="/mnt/speed/the_tracker", master_device=None):
    """
    Creates a git repository in *tracker* adding *builds* in order of their
    build date. If the device name of a build is not *master_device* a branch
    is created.
    """
    rsync_template = 'rsync -avq --delete --exclude=".git" "%s" "%s"'
    created_branches = list()

    if os.path.isdir(tracker):
        shutil.rmtree(tracker)
    mkdirp(tracker)

    subprocess.call('git init "%s"' % tracker, shell=True)

    for current_key in sorted(builds.keys()):
        cmd_list = list()
        build = builds[current_key]

        release_date = build['SYSCONF_BUILD_DATE'].strftime("%Y-%m-%d")
        version      = build['SYSCONF_BUILD_VERSION']
        device       = build['device']
        rsync_cmd    = rsync_template % (build['source_root'] + '/', tracker)

        print "%s : %s" % (current_key, build['source_root'])
        print "+" * 80

        if master_device:
            if device != master_device:
                if device in created_branches:
                    cmd_list.append('git checkout "%s"' % device)
                else:
                    cmd_list.append('git checkout -b "%s"' % device)
                    created_branches.append(device)
            else:
                cmd_list.append('git checkout "master"')

        os.chdir(tracker)
        cmd_list.append(rsync_cmd)
        cmd_list.append("git add .")
        cmd_list.append('git commit -a -m "%s %s %s"' % (device, version, release_date))
        cmd_list.append('git tag -a "%s-%s" -m "%s %s"' % (version, device, device, release_date))

        for command in cmd_list:
            print "Executing '%s'" % command
            subprocess.call(command, shell=True)
        print "-" * 80
        print ""

def list_firmware_archives(available_firmwares):
    """
    List available firmware archives and their build informations.
    """
    print("AVAILABLE ZIP FILES CONTAINING FIRMWARES:")
    print("")

    for device in available_firmwares:
        print " %s" % device
        print "=" * 80
        for version in sorted(available_firmwares[device]):
            current = available_firmwares[device][version]
            image_type = current['image_type']

            print("%(version)-9s: %(filename)s" % current)
            if image_type == 'zip':
                zip_object = zipfile.ZipFile(available_firmwares[device][version]['filename'])
                build_information_file = device + ".ver"
                file_reader = zip_object.open(build_information_file)
                vinfo = get_version_information(file_reader)
            elif image_type == 'pkg':
                vinfo = {'PKG_LOCATION' : current['filename']}
        print ""

def list_firmware_extracted(extracted_root, devices):
    """
    List extracted firmware archives and their build informations.
    """
    all_builds = dict()

    print("AVAILABLE EXTRACTED FIRMWARES:")
    print("")

    for device in devices:
        candidates = glob.glob(os.path.join(extracted_root, "%s/*/*/sysconfig" % device))
        builds = scan_for_build_informations(candidates=candidates, device=device)
        for key in builds:
            all_builds[key] = builds[key]

    for b_key in sorted(all_builds.keys()):
        print("%(device)-15s %(SYSCONF_BUILD_VERSION)s DATE: %(SYSCONF_BUILD_DATE)s ROOT: %(source_root)s" % all_builds[b_key])
    return all_builds

if __name__ == '__main__':

    OPTPARSER = OptionParser()

    OPTPARSER.add_option("-d", "--debug", 
                        dest="debug",
                        help="debug mode", 
                        default=False, action="store_true")

    OPTPARSER.add_option("--no-list-archives", 
                        dest="list_archives",
                        help="List firmware archives", 
                        default=True, action="store_false")
    OPTPARSER.add_option("--no-list-extracted", 
                        dest="list_extracted",
                        help="List extracted firmwares", 
                        default=True, action="store_false")

    OPTPARSER.add_option("--extract", 
                        dest="extract",
                        help="Extract firmware contents", 
                        default=False, action="store_true")
    OPTPARSER.add_option("--tracker", 
                        dest="tracker",
                        help="build git tracker", 
                        default=False, action="store_true")

    PATH_OPTIONS = OptionGroup(OPTPARSER, "Paths")
    PATH_OPTIONS.add_option("-w", "--extraction-root", 
                        dest="working_dir_root",
                        metavar="DIR",
                        help="Directory where firmware contents will be extracted. Default: %default", 
                        default=working_dir_root)
    PATH_OPTIONS.add_option("-b", "--logs", 
                        dest="log_dir",
                        metavar="DIR",
                        help="Directory where binwalk outputs are stored. Default: %default", 
                        default=log_dir)
    PATH_OPTIONS.add_option("-z", "--zips", 
                        dest="zip_dump_dir",
                        metavar="DIR",
                        help="Directory in which the zip files containing the firmware reside. Default: %default", 
                        default=zip_dump_dir)
    PATH_OPTIONS.add_option("-t", "--tracker-root", 
                        dest="git_tracker",
                        metavar="DIR",
                        help="Directory in which the tracker repository resides. Default: %default", 
                        default=git_tracker)
    OPTPARSER.add_option_group(PATH_OPTIONS)


    (OPTIONS, FILES) = OPTPARSER.parse_args()
    (working_dir_root, log_dir, zip_dump_dir, git_tracker) = (OPTIONS.working_dir_root, OPTIONS.log_dir, OPTIONS.zip_dump_dir, OPTIONS.git_tracker)

    actions = []
    if OPTIONS.list_archives:
        actions.append("list archives")
    if OPTIONS.list_extracted:
        actions.append("list extracted")
    if OPTIONS.extract:
        actions.append("extract firmwares")
    if OPTIONS.tracker:
        actions.append("create tracker")
    if len(actions):
        action_desc = ','.join(sorted(actions))
    else:
        action_desc = "None"

    print "=" * 80
    print "Extraction root   : %s" % working_dir_root
    print "Binwalk logs      : %s" % log_dir
    print "Firmware archives : %s" % zip_dump_dir
    print "git Tracker       : %s" % git_tracker
    print "-" * 80
    print "Actions           : %s" % action_desc
    print "=" * 80
    print ""
    print ""

    available_firmwares = scan_for_firmware_images(zip_dump_dir)

    if len(available_firmwares) == 0:
        print "No available firmware images!"
        sys.exit(1)

    if OPTIONS.list_archives:
        list_firmware_archives(available_firmwares)

    if OPTIONS.extract:
        work_firmwares(available_firmwares)

    extracted_root = os.path.join(working_dir_root, "extracted")

    if OPTIONS.list_extracted:
        all_builds = list_firmware_extracted(extracted_root, ["wdtvlivehub", "wdtvlivegen3"])
        print ""

    if OPTIONS.tracker:
        build_git_tracker(all_builds, tracker=git_tracker, master_device="wdtvlivehub")

