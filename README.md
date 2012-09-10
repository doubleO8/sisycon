sisycon
=======

some scripts for WD Live SMP/Hub

wdtv_firmware_extract.py
------------------------

Will extract wd tv live hub/smp firmware images.

Needs [binwalk](https://code.google.com/p/binwalk/), unsquashfs, sudo.
Optional: rsync, git.
Tested with `Binwalk v0.4.3` and `unsquashfs version 4.2 (2011/02/28)`.

Images have to be named `*DEVICE*X*Y*Z*.zip` with `DEVICE` being 'livegen3' or 'livehub' and `X`, `Y` and `Z` being integers representing the version number.
One can get these firmware images from e.g. [WD Rollback site](http://wdc.custhelp.com/app/answers/detail/a_id/5860/~/how-to-roll-back-the-firmware-on-a-wd-tv-live-hub-media-center-or-wd-tv-live).

	Usage: wdtv_firmware_extract.py [options]

	Options:
		-h, --help		show this help message and exit
		-d, --debug		debug mode
		--no-list-archives	List firmware archives
		--no-list-extracted	List extracted firmwares
		--extract		Extract firmware contents
		--tracker		build git tracker

	Paths:
		-w DIR, --extraction-root=DIR
					Directory where firmware contents will be extracted.
					Default: /mnt/speed
		-b DIR, --logs=DIR  Directory where binwalk outputs are stored. Default:
					/filebase/incoming/binwalks
		-z DIR, --zips=DIR  Directory in which the zip files containing the
					firmware reside. Default: /filebase/incoming/dump
		-t DIR, --tracker-root=DIR
					Directory in which the tracker repository resides.
					Default: /mnt/speed/the_branched_tracker
