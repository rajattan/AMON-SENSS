#!/bin/bash
while read -r line
do
 echo "Executing .. :  ./amon -r $line -m 0"
 ./amon -r $line -m 0 

done < <(cat "./file-list")

