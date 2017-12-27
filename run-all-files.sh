#!/bin/bash
i=0
 start_time=$(date +%s)


echo "$1"
while read -r line
do
    cnt=`ps axuw | grep amon | wc | awk '{print $1}'`
    while [ $cnt -ge 10 ] ; do
	dt=`date`
	echo $dt " " $cnt
	sleep 10
	cnt=`ps axuw | grep amon | wc | awk '{print $1}'`
    done
    echo "Executing .. :  ./amon -r $line -m 0"
    nohup ./amon-red -n 5 -r $line -t $2 & #> out$i
done < <(cat "./$1")

end_time=$(date +%s)
diff=$(($start_time - $end_time))
echo " Start: $start_time End: $end_time Diff: $diff File : $1" >> output
