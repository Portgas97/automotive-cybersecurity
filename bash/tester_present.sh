CAN_INTERFACE=$1
CAN_FRAME_ID="7E5"
CAN_FRAME_DATA="02.3E.00.00.00.00.00.00"     

while true; do
    cansend $CAN_INTERFACE $CAN_FRAME_ID#$CAN_FRAME_DATA
    sleep 0.01     # Sleep for 10 milliseconds
done
