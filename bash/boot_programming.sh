CAN_INTERFACE=$1
CAN_FRAME_ID="7E5"
CAN_FRAME_TP="02.3E.00.00.00.00.00.00"     
CAN_FRAME_DCS02="03.1002.00.00.00.00.00"     

while true; do
    # cansend $CAN_INTERFACE $CAN_FRAME_ID#$CAN_FRAME_TP
    cansend $CAN_INTERFACE $CAN_FRAME_ID#$CAN_FRAME_DCS02
    sleep 0.02     # Sleep for 20 milliseconds
done
