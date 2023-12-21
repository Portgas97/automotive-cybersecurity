echo "Starting generating packets on vcan0"
for i in {5..255}; do
	# echo "sequence $i";
	if [ $i == 64 ] 
	then
		cansend vcan0 123#51
		
	elif [ $i < 64 ]
	then 
		cansend vcan0 123#22
		
	elif [ $i > 64 && $i < 128 ]
	then
		cansend vcan0 321#12
		
	else 
		cansend 888#33
	fi
done
echo "finished."
