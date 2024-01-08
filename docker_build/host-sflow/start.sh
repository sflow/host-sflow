#!/bin/sh

COLLECTOR="${COLLECTOR:-127.0.0.1}"
PORT="${PORT:-6343}"
POLLING="${POLLING:-30}"
SAMPLING="${SAMPLING:-1000}"
NET="${NET:-docker}"
DROPMON="${DROPMON:-disable}"
DEBUG="${DEBUG:-none}"

CONF='/etc/hsflowd.conf'

case "$DEBUG" in
  none)
    FLAGS='-d'
    ;;
  info)
    FLAGS='-dd'
    ;;
  fine)
    FLAGS='-ddd'
    ;;
  finer)
    FLAGS='-dddd'
    ;;
  finest)
    FLAGS='-ddddd'
    ;;
  *)
    FLAGS='-d'
    ;;
esac

printf "sflow {\n" > $CONF
printf " sampling=$SAMPLING\n" >> $CONF
printf " sampling.bps_ratio=0\n" >> $CONF
printf " polling=$POLLING\n" >> $CONF
for ip in $COLLECTOR
do
  printf " collector { ip=$ip udpport=$PORT }\n" >> $CONF
done
if [ -e /var/run/docker.sock ]
then
  printf " docker { }\n" >> $CONF
elif [ -e /run/containerd/containerd.sock ]
then
  printf " k8s { markTraffic=on eof=on }\n" >> $CONF
fi
if [ "$DROPMON" = "enable" ]
then
  printf " dropmon { limit=50 start=on sw=on hw=off }\n" >> $CONF
fi
case "$NET" in
  docker)
    printf " pcap { dev=docker0 }\n" >> $CONF
    printf " pcap { dev=docker_gwbridge }\n" >> $CONF
    ;;
  ovs)
    printf " ovs { }\n" >> $CONF
    ;;
  flannel)
    printf " pcap { dev=cni0 }\n" >> $CONF
    ;;
  host)
    printf " tcp { }\n" >> $CONF
    printf " pcap { speed=1G- }\n" >> $CONF
    ;;
  *)
    printf " tcp { }\n" >> $CONF
    for dev in `ls /sys/class/net/ | grep "$NET"`
    do
      printf " pcap { dev=$dev }\n" >> $CONF
    done
    ;;
esac
printf "}\n" >> $CONF

echo "Sending sFlow to $COLLECTOR UDP port $PORT"
exec /usr/sbin/hsflowd $FLAGS
