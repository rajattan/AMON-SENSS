#!/bin/bash
i=0
while read -r line
do
# i=$(($i+1))
 echo "Executing .. :  ./amon -r $line -m 0"
 ./amon -r $line -m 0 #> out$i

done < <(cat "./file-list")

