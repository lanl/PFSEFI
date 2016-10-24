#! /bin/bash
OUTPUTFILE=result
COUNT=20
rm result
until [ $COUNT -lt 0 ]
do
  ./foo >> result
  let COUNT-=1
done
