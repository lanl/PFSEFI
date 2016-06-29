import fileinput
import re
for lin in fileinput.input(inplace=1):
  if line.find(
with open("SEFI_conf.ini", "r") as config
  config_lines = list(config)
  with open
lines = list(config_text)
# The probability is *currently* on the 50th line in the ini file
line = lines[50]
# search for a decimal number
num = re.search("\d*[.]\d+", line)
prob = line[num.start():num.end()]
prob += .0005

