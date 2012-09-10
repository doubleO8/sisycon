#!/bin/sh
d=`date +"%Y-%m-%d_%H%M"`
h=`hostname`
source /sysconfig
OUT_ROOT=`pwd -L`
TYPE=`echo $SYSCONF_FIRMWARE_BIN | cut -d . -f 0`

echo "== device type"
echo ""

if [ "x$TYPE" == "xwdtvlivegen3" ]; then
	echo "     ** WD TV Live SMP **"
else
	if [ "x$TYPE" == "xwdtvlivehub" ]; then
		echo "    ** WD TV Live Hub **"
	else
		echo "!! Unknown type: $TYPE"
		exit 99
	fi
fi

echo ""
BN="${TYPE}-${h}-${d}"
LOG_DIR="${OUT_ROOT}/log"
RSYNC_TARGET_DIR="${OUT_ROOT}/snapshot/${BN}/"
EXCLUDES="--exclude=/tmp/media --exclude="${OUT_ROOT}/snapshot/" --exclude=/usrdata/.wd_tv/wdcm/ --exclude=/tmp/WDTVPriv/.wd_tv/wdcm/ --exclude=/usrdata/rootfs/ --exclude=/proc --exclude=/sys"

echo "== creating RSYNC_TARGET_DIR '${RSYNC_TARGET_DIR}'"
mkdir -p $RSYNC_TARGET_DIR

echo "== creating LOG_DIR          '${LOG_DIR}'"
mkdir -p ${LOG_DIR}

RSYNC_COMMAND="rsync -av / ${RSYNC_TARGET_DIR} ${EXCLUDES} --delete-excluded --log-file=${LOG_DIR}/${BN}.rsync.log"
echo "== running rsync command:"
echo "${RSYNC_COMMAND}"
echo ""
${RSYNC_COMMAND}
