echo "Starting generating packets on vcan0"
for i in {0..255}; do
	# echo "sequence $i";
	if [ $i == 8 ] 
	then
		cansend vcan0 123#50
	elif [ $i > 128 ]
	then 
		cansend vcan0 123#22
	else
		cansend vcan0 321#aa
	fi
done
echo "finished."
