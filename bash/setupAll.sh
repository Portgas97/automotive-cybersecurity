echo "setting keyboard to IT"
setxkbmap it

echo "setting can0"
ip link set can0 down
ip link set can0 type can bitrate 500000
ip link set can0 up

echo "setting can1"
ip link set can1 down
ip link set can1 type can bitrate 500000
ip link set can1 up

echo "restarting aactexpress.service"
systemctl restart aactexpress.service

echo "configuring eth0"
ifconfig eth0 up
ifconfig eth0 192.168.0.10
ifconfig eth0 netmask 255.255.255.0
ifconfig eth0 broadcast 192.168.0.255
route add default gw 192.168.0.1

read -r -p "start testerPresent and KeepAlive scripts(y0 = yes on can0)(y1 = yes on can1)? [y0/y1/n]" response
case "$response" in
    [yY][0]|[0])
        bash /home/kali/AACT/tools/tci/keepalive_dinamic.sh can0 &
        ID=$!
        # python /home/kali/AACT/tools/CANtools/python/diagnostic_state.py -c can0 -i 0x714 -t 0.5
        # kill -9 $ID
        ;;
    [yY][1]|[1])
        bash /home/kali/AACT/tools/tci/keepalive_dinamic.sh can1 &
        ID=$!
        # python /home/kali/AACT/tools/CANtools/python/diagnostic_state.py -c can1 -i 0x714 -t 0.5
        # kill -9 $ID
        ;;
    *)
        ;;
    
esac
